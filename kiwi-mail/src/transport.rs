//! TCP + TLS transport with full negotiated-parameter capture.
//!
//! Every mail connection produces a [`TlsObservation`] that feeds
//! `kiwi_core`'s `SecuritySession`. This module is the single place where
//! TLS is negotiated for mail protocols — never bypass it.
//!
//! Certificate validation still uses webpki (rustls' verifier); a thin
//! [`RecordingVerifier`] captures the verdict for the trust engine before
//! rustls decides whether to complete the handshake. `accept_invalid_certs`
//! exists **only** so the client can connect to test fixtures with
//! self-signed certs — it records the failure loudly rather than hiding it.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::{MailError, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Anything the protocol clients can read/write — TCP, TLS, or a test double.
pub trait MailStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> MailStream for T {}

/// Negotiated security parameters captured after a TLS handshake.
/// Deterministic facts only — scoring/decisions live in kiwi-core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsObservation {
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    /// IANA cipher-suite code point when known (e.g. 0x1302).
    pub cipher_suite_iana: Option<u16>,
    pub key_exchange_group: Option<String>,
    pub alpn_protocol: Option<Vec<u8>>,
    /// DER-encoded peer certificate chain, leaf first.
    pub peer_certificates: Vec<Vec<u8>>,
    /// Whether the session started plaintext and upgraded via STARTTLS/STLS.
    pub upgraded_via_starttls: bool,
    /// Certificate-chain validation verdict recorded during the handshake.
    /// `None` when no TLS handshake occurred.
    pub cert_verdict: Option<CertVerdict>,
}

/// Recorded outcome of webpki chain validation — the transport analogue of
/// `kiwi_core::session::ChainValidation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertVerdict {
    Valid,
    Invalid,
    Untrusted,
    Expired,
    HostnameMismatch,
    Unknown,
}

/// TLS policy for a connection. Defaults are strict: webpki roots, real
/// hostname verification, no ALPN (mail protocols don't negotiate ALPN).
#[derive(Debug, Clone, Default)]
pub struct TlsSettings {
    /// Test/dev escape hatch: complete the handshake even when validation
    /// fails, but still record the real verdict. Never enabled silently —
    /// callers must set it explicitly.
    pub accept_invalid_certs: bool,
    /// Extra trust anchors (e.g. a local test CA fixture).
    pub extra_roots: Vec<Vec<u8>>,
}

/// Socket security mode chosen by account config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketSecurity {
    Plaintext,
    /// TLS from connect (e.g. 465/993/995).
    ImplicitTls,
    /// Plaintext first, then STARTTLS/STLS upgrade.
    StartTls,
}

/// A live connection: stream + everything we know about its security.
pub struct Transport {
    stream: Box<dyn MailStream>,
    security: SocketSecurity,
    host: String,
    port: u16,
    observation: Option<TlsObservation>,
    tls_settings: TlsSettings,
}

impl Transport {
    /// Connect per `security`. For `StartTls` this connects plaintext only —
    /// the protocol client must call [`starttls_upgrade`](Self::starttls_upgrade)
    /// after the protocol-level STARTTLS/STLS command succeeds.
    pub async fn connect(
        host: &str,
        port: u16,
        security: SocketSecurity,
        tls_settings: TlsSettings,
    ) -> Result<Self> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
            .await
            .map_err(|_| MailError::Io(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")))?
            .map_err(MailError::Io)?;

        let mut t = Self {
            stream: Box::new(stream),
            security,
            host: host.to_string(),
            port,
            observation: None,
            tls_settings,
        };
        if security == SocketSecurity::ImplicitTls {
            t.tls_wrap(false).await?;
        }
        Ok(t)
    }

    /// Upgrade the live plaintext stream to TLS (STARTTLS/STLS). Captures a
    /// fresh [`TlsObservation`]; the pre-upgrade one is discarded — the
    /// observable security of this session is the post-upgrade state.
    pub async fn starttls_upgrade(&mut self) -> Result<()> {
        if self.security != SocketSecurity::StartTls {
            return Err(MailError::Protocol {
                protocol: "transport",
                detail: "STARTTLS upgrade on non-STARTTLS socket".into(),
            });
        }
        self.tls_wrap(true).await
    }

    async fn tls_wrap(&mut self, via_starttls: bool) -> Result<()> {
        let stream = std::mem::replace(&mut self.stream, Box::new(tokio::io::empty()));
        let (stream, obs) =
            tls_handshake(stream, &self.host, &self.tls_settings, via_starttls).await?;
        self.stream = stream;
        self.observation = Some(obs);
        Ok(())
    }

    /// Build a `Transport` around an arbitrary stream (test doubles).
    /// `security`/`host`/`port` describe what the stream *represents*.
    pub fn from_stream(
        stream: impl MailStream + 'static,
        host: &str,
        port: u16,
        security: SocketSecurity,
        tls_settings: TlsSettings,
    ) -> Self {
        Self {
            stream: Box::new(stream),
            security,
            host: host.to_string(),
            port,
            observation: None,
            tls_settings,
        }
    }

    pub fn observation(&self) -> Option<&TlsObservation> {
        self.observation.as_ref()
    }

    pub fn is_encrypted(&self) -> bool {
        self.observation.is_some()
    }

    /// Configured socket-security mode (does not change after upgrade —
    /// check `is_encrypted()`/`observation()` for live state).
    pub fn socket_security(&self) -> SocketSecurity {
        self.security
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Detach the underlying stream (e.g. when handing the socket to an
    /// upgraded state machine). Security metadata stays on the Transport.
    pub fn into_stream(self) -> Box<dyn MailStream> {
        self.stream
    }
}

// Let protocol code use `Transport` directly as its IO object.
impl AsyncRead for Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_shutdown(cx)
    }
}

/// Wrap a stream in a rustls client handshake and capture the observation.
async fn tls_handshake(
    stream: Box<dyn MailStream>,
    host: &str,
    settings: &TlsSettings,
    via_starttls: bool,
) -> Result<(Box<dyn MailStream>, TlsObservation)> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for der in &settings.extra_roots {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| MailError::Tls(RustlsError::General(format!("bad extra root: {e}"))))?;
    }

    let webpki = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| MailError::Tls(RustlsError::General(format!("verifier build: {e}"))))?;
    let verdict_slot: Arc<Mutex<Option<CertVerdict>>> = Arc::new(Mutex::new(None));
    let verifier = RecordingVerifier {
        inner: webpki,
        verdict_slot: verdict_slot.clone(),
        accept_invalid: settings.accept_invalid_certs,
    };

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    // Deterministic, inspectable defaults; no ALPN for mail protocols.
    config.alpn_protocols = Vec::new();

    let server_name = server_name_for(host)?;
    let connector = TlsConnector::from(Arc::new(config));
    let tls_stream =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name, stream))
            .await
            .map_err(|_| {
                MailError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TLS handshake timeout",
                ))
            })?
            .map_err(|e| {
                let verdict = *verdict_slot.lock().unwrap();
                match verdict {
                    Some(v) => MailError::Tls(RustlsError::General(format!(
                        "certificate rejected ({v:?}): {e}"
                    ))),
                    None => MailError::Tls(RustlsError::General(format!("handshake failed: {e}"))),
                }
            })?;

    let (_, conn) = tls_stream.get_ref();
    let obs = TlsObservation {
        protocol_version: conn.protocol_version().map(|v| format!("{v:?}")),
        cipher_suite: conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite())),
        cipher_suite_iana: conn
            .negotiated_cipher_suite()
            .and_then(|s| iana_cipher_id(s.suite())),
        key_exchange_group: conn
            .negotiated_key_exchange_group()
            .map(|g| format!("{:?}", g.name())),
        alpn_protocol: conn.alpn_protocol().map(|p| p.to_vec()),
        peer_certificates: conn
            .peer_certificates()
            .map(|c| c.iter().map(|d| d.as_ref().to_vec()).collect())
            .unwrap_or_default(),
        upgraded_via_starttls: via_starttls,
        cert_verdict: *verdict_slot.lock().unwrap(),
    };
    Ok((Box::new(tls_stream), obs))
}

fn server_name_for(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string()).map_err(|_| MailError::Protocol {
        protocol: "transport",
        detail: format!("invalid TLS server name: {host:?}"),
    })
}

/// IANA code points for the suites rustls can negotiate. Unknown suites
/// surface as `None` — we never guess.
fn iana_cipher_id(suite: rustls::CipherSuite) -> Option<u16> {
    use rustls::CipherSuite::*;
    Some(match suite {
        TLS13_AES_128_GCM_SHA256 => 0x1301,
        TLS13_AES_256_GCM_SHA384 => 0x1302,
        TLS13_CHACHA20_POLY1305_SHA256 => 0x1303,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 0xC02B,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 0xC02C,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 0xCCA9,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 0xC02F,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 0xC030,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xCCA8,
        _ => return None,
    })
}

/// Observes webpki's verdict so the trust engine sees the real certificate
/// story even when the connection is allowed to proceed (test fixtures) —
/// and equally when it is correctly rejected (production default).
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    verdict_slot: Arc<Mutex<Option<CertVerdict>>>,
    accept_invalid: bool,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(v) => {
                *self.verdict_slot.lock().unwrap() = Some(CertVerdict::Valid);
                Ok(v)
            }
            Err(e) => {
                *self.verdict_slot.lock().unwrap() = Some(map_cert_error(&e));
                if self.accept_invalid {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(e)
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn map_cert_error(e: &RustlsError) -> CertVerdict {
    use rustls::CertificateError as Ce;
    match e {
        RustlsError::InvalidCertificate(ce) => match ce {
            Ce::Expired | Ce::NotValidYet => CertVerdict::Expired,
            Ce::NotValidForName | Ce::NotValidForNameContext { .. } => {
                CertVerdict::HostnameMismatch
            }
            Ce::UnknownIssuer => CertVerdict::Untrusted,
            _ => CertVerdict::Invalid,
        },
        _ => CertVerdict::Invalid,
    }
}
