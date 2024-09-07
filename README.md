# Russh + Axum + tcpip_forward!

A Rust project demonstrating how to serve Axum's HTTP server on a remote host's port, using SSH tunneling and streaming to avoid opening a socket on the client.

Tokio, Tower, and hyper are responsible for gluing everything together with async. They are pretty awesome!

## Usage

With [`localhost.run`](https://localhost.run/):

```sh
cargo run -- localhost.run -i ~/.ssh/id_ed25519 -l username --request-pty ""
```

With [`sish`](https://github.com/antoniomika/sish):

```sh
cargo run -- tuns.sh -i ~/.ssh/id_ed25519 -R test
```
