# Russh + Axum + tcpip_forward!

A Rust project demonstrating how to serve Axum's HTTP server on a remote host's port, using SSH tunneling and streaming to avoid opening a socket on the client.

Tokio, Tower, hyper, and `async` are responsible for gluing everything together. They are pretty awesome! The hardest part to implement was Axum's half; mainly, figuring out how to accept a streaming socket instead of the default TcpListener.
