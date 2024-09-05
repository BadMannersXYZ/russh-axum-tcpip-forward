use std::{
    iter,
    path::PathBuf,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use axum::{
    extract::State,
    routing::{get, RouterIntoService},
    Router,
};
use clap::Parser;
use futures::future::poll_fn;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use russh::{
    client::{self, Config, Handle, Msg, Session},
    keys::{
        decode_secret_key,
        key::{self, KeyPair},
    },
    Channel, ChannelMsg, Disconnect,
};
use tokio::{fs, time::sleep};
use tower::Service;
use tracing::{debug, debug_span, error, info, trace, warn};

/* Entrypoint */

/// Remote port forwarding (reverse tunneling) with Russh to serve an Axum application.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct ClapArgs {
    /// SSH hostname
    #[arg(short = 'H', long)]
    host: String,

    /// SSH port
    #[arg(short, long, default_value_t = 22)]
    port: u16,

    /// Identity file containing private key
    #[arg(short, long)]
    identity_file: PathBuf,

    /// Remote hostname to bind to
    #[arg(short, long, default_value_t = String::from("localhost"))]
    remote_host: String,

    /// Remote port to bind to
    #[arg(short = 't', long, default_value_t = 80)]
    remote_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber)?;
    trace!("Tracing is up!");
    let args = ClapArgs::parse();
    let secret_key = fs::read_to_string(args.identity_file)
        .await
        .with_context(|| "Failed to open secret key")?;
    let secret_key = decode_secret_key(&secret_key, None).with_context(|| "Invalid secret key")?;
    let config = Arc::new(client::Config {
        ..Default::default()
    });
    let mut session =
        TcpForwardSession::connect(&args.host, args.port, config, Arc::new(secret_key))
            .await
            .with_context(|| "Initial connection failed")?;
    loop {
        match session
            .start_forwarding(&args.remote_host, args.remote_port)
            .await
        {
            Err(e) => error!(error = ?e, "TCP forward session failed."),
            _ => info!("Connection closed."),
        }
        debug!("Attempting graceful disconnect.");
        if let Err(e) = session.close().await {
            debug!(error = ?e, "Graceful disconnect failed.")
        }
        debug!("Restarting connection.");
        let mut reconnect_attempt = 0u64;
        session = session
            .reconnect_with(
                &args.host,
                args.port,
                iter::from_fn(move || {
                    reconnect_attempt += 1;
                    if reconnect_attempt <= 5 {
                        Some(Duration::from_secs(2 * reconnect_attempt))
                    } else {
                        None
                    }
                }),
            )
            .await
            .with_context(|| "Reconnection failed.")?;
    }
}

/* Axum router */

#[derive(Clone)]
struct AppState {
    data: Arc<Mutex<usize>>,
}

/// A function that creates our Axum router.
fn router_factory(state: AppState) -> Router {
    Router::new().route("/", get(hello)).with_state(state)
}

/// A lazily-created Router, to be used by the SSH client tunnels.
static ROUTER: LazyLock<Router> = LazyLock::new(|| {
    router_factory(AppState {
        data: Arc::new(Mutex::new(0)),
    })
});

/// A basic example endpoint that includes shared state.
async fn hello(State(state): State<AppState>) -> String {
    let mut request_id = state.data.lock().unwrap();
    *request_id += 1;
    debug!(id = %request_id, "GET /");
    format!("Hello, request #{}!", request_id)
}

/* Russh session and client */

/// User-implemented session type as a helper for interfacing with the SSH protocol.
struct TcpForwardSession {
    config: Arc<Config>,
    secret_key: Arc<KeyPair>,
    session: Handle<Client>,
}

/// User-implemented session type as a helper for interfacing with the SSH protocol.
impl TcpForwardSession {
    /// Creates a connection with the SSH server.
    async fn connect(
        host: &str,
        port: u16,
        config: Arc<Config>,
        secret_key: Arc<KeyPair>,
    ) -> Result<Self> {
        let span = debug_span!("TcpForwardSession.connect");
        let _enter = span;
        debug!("TcpForwardSession connecting...");
        let client = Client {};
        let mut session = client::connect(Arc::clone(&config), (host, port), client)
            .await
            .with_context(|| "Unable to connect to remote host.")?;
        if !session
            .authenticate_publickey("root", Arc::clone(&secret_key))
            .await
            .with_context(|| "Authentication error.")?
        {
            return Err(anyhow!("Authentication failed."));
        }
        Ok(Self {
            config,
            session,
            secret_key,
        })
    }

    /// Sends a port forwarding request and opens a session to receive miscellaneous data.
    /// The function yields when the session is broken (for example, if the connection was lost).
    async fn start_forwarding(&mut self, remote_host: &str, remote_port: u16) -> Result<()> {
        let span = debug_span!("TcpForwardSession.start");
        let _enter = span;
        self.session
            .tcpip_forward(remote_host, remote_port.into())
            .await
            .with_context(|| "tcpip_forward error.")?;
        let mut channel = self
            .session
            .channel_open_session()
            .await
            .with_context(|| "channel_open_session error.")?;
        loop {
            let Some(msg) = channel.wait().await else {
                return Err(anyhow!("Unexpected end of channel."));
            };
            match msg {
                ChannelMsg::Data { data } => {
                    print!("{}", String::from_utf8_lossy(&data));
                }
                ChannelMsg::Close => break,
                msg => return Err(anyhow!("Unknown message type {:?}.", msg)),
            }
        }
        Ok(())
    }

    /// Attempts to reconnect to the SSH server.
    ///
    /// Our reconnection strategy comes from an iterator which yields `Duration`s, which tell us how long to delay
    /// our next reconnection attempt for. The function will stop attempting to reconnect once the iterator
    /// stops yielding values.
    async fn reconnect_with(
        self,
        host: &str,
        port: u16,
        timer_iterator: impl Iterator<Item = Duration>,
    ) -> Result<Self> {
        let TcpForwardSession {
            config, secret_key, ..
        } = self;
        match TcpForwardSession::connect(host, port, config.clone(), secret_key.clone()).await {
            Err(err) => {
                let mut e = err;
                for (i, duration) in timer_iterator.enumerate() {
                    sleep(duration).await;
                    trace!("Reconnection attempt #{}...", i + 1);
                    e = match TcpForwardSession::connect(
                        host,
                        port,
                        config.clone(),
                        secret_key.clone(),
                    )
                    .await
                    {
                        Err(e) => e,
                        session => {
                            debug!(reconnection_attempts = i + 1, "Succeeded on reconnecting.");
                            return session;
                        }
                    }
                }
                warn!("Backing off from reconnection attempt.");
                Err(e)
            }
            session => {
                debug!("Reconnected on first attempt.");
                session
            }
        }
    }

    async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

/// Our SSH client implementing the `Handler` callbacks for the functions we need to use.
struct Client {}

#[async_trait]
impl client::Handler for Client {
    type Error = anyhow::Error;

    /// Always accept the SSH server's pubkey. Don't do this in production.
    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    /// Handle a new forwarded connection, represented by a specific `Channel`. We will create a clone of our router,
    /// and forward any messages from this channel with its streaming API.
    ///
    /// To make Axum behave with streaming, we must turn it into a Tower service first.
    /// And to handle the SSH channel as a stream, we will use a utility method from Tokio that turns our
    /// AsyncRead/Write stream into a `hyper` IO object.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let span = debug_span!("server_channel_open_forwarded_tcpip",);
        let _enter = span.enter();
        debug!(
            sshid = %String::from_utf8_lossy(session.remote_sshid()),
            connected_address = connected_address,
            connected_port = connected_port,
            originator_address = originator_address,
            originator_port = originator_port,
            "New connection!"
        );
        // Get our router from the lazy static.
        let mut router: RouterIntoService<Incoming> =
            <Router as Clone>::clone(&*ROUTER).into_service::<Incoming>();
        poll_fn(|cx| router.poll_ready(cx)).await.unwrap();
        let service = service_fn(move |req| {
            // Cloning our service for each call is required, given that service_fn expects Fn instead of FnMut.
            // This should be fine performance-wise, since RouterIntoService is a thin wrapper around Router,
            // which itself is a thin wrapper around Arc<RouterInner<_>>.
            let mut router = router.clone();
            async move { router.call(req).await }
        });
        let socket = TokioIo::new(channel.into_stream());
        let server = Builder::new(TokioExecutor::new());
        // I'm not really sure why tokio::spawn is necessary here, but it doesn't work otherwise.
        // My guess is that we block on TcpForwardSession.start_forwarding_with().
        // We use `serve_connection_with_upgrades` to allow upgrading to WebSocket - which will still run through
        // our SSH tunnel for every message!
        tokio::spawn(async move {
            server
                .serve_connection_with_upgrades(socket, service)
                .await
                .unwrap();
        });
        Ok(())
    }
}
