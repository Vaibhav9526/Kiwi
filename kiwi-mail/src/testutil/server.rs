//! Scripted server side of a transcript — `Wire` over plain or
//! TLS-upgraded duplex streams, `serve` (drives + asserts the
//! script), `spawn_script`, and a self-signed `tls_acceptor` for
//! TLS-boundary fixtures.

use std::io;

use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio_rustls::TlsAcceptor;

use crate::lines::read_line;

use super::script::*;

enum Wire {
    Plain(DuplexStream),
    Tls(Box<tokio_rustls::server::TlsStream<DuplexStream>>),
}

impl Wire {
    async fn rl(&mut self, scratch: &mut Vec<u8>) -> crate::error::Result<Vec<u8>> {
        match self {
            Wire::Plain(s) => read_line(s, scratch, "fixture").await,
            Wire::Tls(s) => read_line(&mut **s, scratch, "fixture").await,
        }
    }
    async fn wl(&mut self, b: &[u8]) -> io::Result<()> {
        match self {
            Wire::Plain(s) => s.write_all(b).await,
            Wire::Tls(s) => s.write_all(b).await,
        }
    }
}

/// Drive the server side of a transcript. Asserts each `C:` line
/// (protocol-aware matching); returns Err describing the first divergence.
pub async fn serve(
    end: DuplexStream,
    steps: &[Step],
    proto: Proto,
    tls: Option<TlsAcceptor>,
) -> Result<(), String> {
    let mut wire = Wire::Plain(end);
    let mut scratch = Vec::new();
    let mut last_tag = String::new();
    for step in steps {
        match step {
            Step::Server(bytes) => {
                let bytes = if proto == Proto::Imap && !last_tag.is_empty() {
                    rewrite_tag(bytes, &last_tag)
                } else {
                    bytes.clone()
                };
                wire.wl(&bytes).await.map_err(|e| e.to_string())?;
            }
            Step::TlsBoundary => {
                let acc = tls
                    .as_ref()
                    .ok_or("transcript marks a TLS boundary but no acceptor was given")?;
                let plain = match wire {
                    Wire::Plain(s) => s,
                    Wire::Tls(_) => return Err("second TLS boundary".into()),
                };
                let t = acc
                    .accept(plain)
                    .await
                    .map_err(|e| format!("tls accept: {e}"))?;
                wire = Wire::Tls(Box::new(t));
            }
            Step::Client(expected) => loop {
                let line = wire.rl(&mut scratch).await.map_err(|e| e.to_string())?;
                let actual = String::from_utf8_lossy(&line).into_owned();
                if proto == Proto::Imap {
                    // Track the client's tag — but only real tag-shaped
                    // tokens (letters+digits), never payload lines like
                    // APPEND bodies or DONE.
                    let tok = actual.split_whitespace().next().unwrap_or("");
                    if tok.len() > 1
                        && tok.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
                        && tok.bytes().any(|b| b.is_ascii_digit())
                    {
                        last_tag = tok.to_string();
                    }
                }
                if client_matches(proto, expected, &actual) {
                    break;
                }
                match offscript_reply(proto, &actual) {
                    Some(reply) => wire.wl(&reply).await.map_err(|e| e.to_string())?,
                    None => {
                        return Err(format!(
                            "transcript divergence: expected {expected:?}, client sent {actual:?}"
                        ));
                    }
                }
            },
        }
    }
    Ok(())
}

/// Spawn a scripted server from an inline `S:`/`C:` transcript string.
pub fn spawn_script(
    end: DuplexStream,
    proto: Proto,
    script: &str,
    tls: Option<TlsAcceptor>,
) -> tokio::task::JoinHandle<Result<(), String>> {
    let steps = parse(script);
    tokio::spawn(async move { serve(end, &steps, proto, tls).await })
}

/// Self-signed TLS acceptor + DER for transcript tests that cross a
/// TLS boundary. `names` must cover the client's server_name.
pub fn tls_acceptor(names: &[&str]) -> (TlsAcceptor, Vec<u8>) {
    let certified =
        rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    let der = certified.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    (
        TlsAcceptor::from(std::sync::Arc::new(cfg)),
        der.as_ref().to_vec(),
    )
}
