//! SMTP send client (RFC 5321): EHLO → STARTTLS → AUTH → MAIL/RCPT/DATA.
//!
//! Security notes:
//! - `require_starttls` (default on) fails closed when a `StartTls` socket
//!   meets a server that doesn't advertise STARTTLS — no silent downgrade.
//! - Envelope addresses are validated against CRLF/header injection.
//! - Credentials live in zeroizing buffers; replies are never logged with
//!   auth material attached (SECURITY.md rules 6, 9).
//! - AUTH PLAIN/LOGIN credentials are only sent over an encrypted transport
//!   unless the caller explicitly constructs `SocketSecurity::Plaintext`
//!   *and* sets `allow_plaintext_auth` — the default refuses.

use std::collections::BTreeMap;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::transport::Transport;

const PROTO: &str = "smtp";
const CMD_TIMEOUT: Duration = Duration::from_secs(120);
/// RFC 5321 §4.5.3.2 recommends ≥10 min after the final "." — we use 5 min.
const DATA_TIMEOUT: Duration = Duration::from_secs(300);
/// Bound on reply lines a server may send for one command.
const MAX_REPLY_LINES: usize = 200;

mod client;
mod commands;

pub use commands::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpReply {
    pub code: u16,
    /// Text after the code (enhanced status code stripped into `enhanced`).
    pub lines: Vec<String>,
    /// RFC 3463 enhanced code (e.g. "5.7.8") when present on the first line.
    pub enhanced: Option<String>,
}

impl SmtpReply {
    pub fn is_success(&self) -> bool {
        (200..400).contains(&self.code)
    }
    /// 4xx = transient failure; retry later is legitimate.
    pub fn is_transient(&self) -> bool {
        (400..500).contains(&self.code)
    }
    /// 5xx = permanent failure.
    pub fn is_permanent(&self) -> bool {
        (500..600).contains(&self.code)
    }
    pub fn message(&self) -> String {
        self.lines.join(" ")
    }
}

/// Parsed EHLO extension advertisement.
#[derive(Debug, Clone, Default)]
pub struct EhloInfo {
    /// First EHLO line — the server's greeting/domain text.
    pub greeting: String,
    /// Uppercased extension keyword → parameter string ("" if none).
    pub extensions: BTreeMap<String, String>,
}

impl EhloInfo {
    pub fn supports(&self, ext: &str) -> bool {
        self.extensions.contains_key(&ext.to_ascii_uppercase())
    }
    pub fn has_starttls(&self) -> bool {
        self.supports("STARTTLS")
    }
    /// Advertised AUTH mechanisms, uppercased (from `AUTH`/`AUTH=` lines).
    pub fn auth_mechanisms(&self) -> Vec<String> {
        for key in ["AUTH", "AUTH="] {
            if let Some(v) = self.extensions.get(key) {
                return v
                    .split_whitespace()
                    .map(|s| s.to_ascii_uppercase())
                    .collect();
            }
        }
        Vec::new()
    }
    /// SIZE parameter (max message bytes) when advertised.
    pub fn max_size(&self) -> Option<u64> {
        self.extensions
            .get("SIZE")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    }
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// Refuse to continue when the server doesn't offer STARTTLS on a
    /// `SocketSecurity::StartTls` connection. Default true (fail closed).
    pub require_starttls: bool,
    /// Explicit opt-in for sending AUTH over plaintext. Default false.
    pub allow_plaintext_auth: bool,
    /// Client name sent in EHLO.
    pub client_name: String,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            require_starttls: true,
            allow_plaintext_auth: false,
            client_name: "kiwi.local".into(),
        }
    }
}

/// Authentication credentials. Secrets are zeroizing and never `Debug`-printed.
pub enum SmtpAuth {
    None,
    Plain {
        user: String,
        password: Zeroizing<String>,
    },
    Login {
        user: String,
        password: Zeroizing<String>,
    },
    /// OAuth2 bearer token (XOAUTH2 SASL).
    XOAuth2 {
        user: String,
        token: Zeroizing<String>,
    },
}

pub struct SmtpClient {
    t: Transport,
    config: SmtpConfig,
    ehlo: Option<EhloInfo>,
    scratch: Vec<u8>,
}

/// One outbound message: envelope + complete MIME bytes (CRLF endings).
pub struct SendRequest {
    pub from: String,
    pub to: Vec<String>,
    /// Full RFC 5322 message produced by `crate::mime`.
    pub message: Vec<u8>,
}

/// Per-recipient outcome of one DATA transaction.
#[derive(Debug)]
pub struct SendOutcome {
    pub accepted: Vec<String>,
    /// (recipient, server reply) pairs the server rejected.
    pub rejected: Vec<(String, SmtpReply)>,
    /// Server's final reply to the DATA body (when reached).
    pub data_reply: Option<SmtpReply>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MailError;
    use crate::lines::read_line;
    use crate::transport::{SocketSecurity, TlsSettings};
    use base64::Engine;
    use tokio::io::AsyncWriteExt;
    use tokio::io::duplex;

    fn transport_for(server: tokio::io::DuplexStream) -> Transport {
        Transport::from_stream(
            server,
            "mail.example.test",
            25,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        )
    }

    #[tokio::test]
    async fn ehlo_parses_extensions() {
        let (client_end, mut server_end) = duplex(8192);
        tokio::spawn(async move {
            server_end
                .write_all(b"220 mx.example.test ESMTP ready\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end
                .write_all(
                    b"250-mx.example.test greets you\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10485760\r\n",
                )
                .await
                .unwrap();
        });
        let mut c = SmtpClient::connect(transport_for(client_end), SmtpConfig::default())
            .await
            .unwrap();
        let ehlo = c.ehlo_info().unwrap();
        assert!(ehlo.has_starttls());
        assert_eq!(ehlo.auth_mechanisms(), vec!["PLAIN", "LOGIN"]);
        assert_eq!(ehlo.max_size(), Some(10_485_760));
        c.quit().await.unwrap();
    }

    #[tokio::test]
    async fn starttls_required_fails_closed() {
        let (client_end, mut server_end) = duplex(8192);
        tokio::spawn(async move {
            server_end
                .write_all(b"220 mx.example.test ESMTP\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end
                .write_all(b"250 mx.example.test\r\n")
                .await
                .unwrap();
        });
        let t = Transport::from_stream(
            client_end,
            "mail.example.test",
            587,
            SocketSecurity::StartTls,
            TlsSettings::default(),
        );
        match SmtpClient::connect(t, SmtpConfig::default()).await {
            Err(e) => assert!(matches!(e, MailError::Protocol { .. })),
            Ok(_) => panic!("connect must fail closed without STARTTLS"),
        }
    }

    #[tokio::test]
    async fn plaintext_auth_refused_by_default() {
        let (client_end, mut server_end) = duplex(8192);
        tokio::spawn(async move {
            server_end.write_all(b"220 mx\r\n250 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
        });
        let mut c = SmtpClient::connect(transport_for(client_end), SmtpConfig::default())
            .await
            .unwrap();
        let auth = SmtpAuth::Plain {
            user: "u".into(),
            password: Zeroizing::new("p".into()),
        };
        assert!(matches!(
            c.authenticate(&auth).await,
            Err(MailError::Protocol { .. })
        ));
    }

    #[tokio::test]
    async fn send_mail_dot_stuffs_and_reports_rejections() {
        let (client_end, mut server_end) = duplex(1 << 20);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            server_end.write_all(b"220 mx\r\n").await.unwrap();
            // EHLO
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"250 mx\r\n").await.unwrap();
            // MAIL FROM
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"250 2.1.0 ok\r\n").await.unwrap();
            // RCPT 1 ok, RCPT 2 rejected
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"250 2.1.5 ok\r\n").await.unwrap();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end
                .write_all(b"550 5.1.1 no such user\r\n")
                .await
                .unwrap();
            // DATA
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"354 go\r\n").await.unwrap();
            // read dot-terminated body
            loop {
                let l = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
                if l == b"." {
                    break;
                }
            }
            server_end.write_all(b"250 2.0.0 queued\r\n").await.unwrap();
        });

        let mut c = SmtpClient::connect(
            transport_for(client_end),
            SmtpConfig {
                allow_plaintext_auth: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let req = SendRequest {
            from: "me@example.test".into(),
            to: vec!["ok@x.test".into(), "bad@x.test".into()],
            message: b"Subject: t\r\n\r\nstarts with dot\r\n.danger\r\n".to_vec(),
        };
        let out = c.send_mail(&req).await.unwrap();
        assert_eq!(out.accepted, vec!["ok@x.test"]);
        assert_eq!(out.rejected.len(), 1);
        assert_eq!(out.rejected[0].1.code, 550);
        assert_eq!(out.data_reply.unwrap().code, 250);
    }

    #[test]
    fn envelope_injection_rejected() {
        assert!(validate_envelope("a@b", &["x@y".to_string()]).is_ok());
        assert!(validate_envelope("a@b\r\nRCPT TO:<evil>", &["x@y".into()]).is_err());
        assert!(validate_envelope("a@b", &[]).is_err());
        assert!(validate_envelope("", &["x@y".into()]).is_err());
    }

    #[test]
    fn dot_stuffing() {
        assert_eq!(dot_stuff(b"a\r\n.b\r\n"), b"a\r\n..b\r\n");
        assert_eq!(dot_stuff(b".lead"), b"..lead");
    }

    #[test]
    fn send_queue_undo_and_due() {
        let mut q = SendQueue::new();
        q.enqueue(QueuedSend {
            queue_id: "q1".into(),
            request: SendRequest {
                from: "a".into(),
                to: vec!["b".into()],
                message: vec![],
            },
            not_before_unix: 100,
            undo_window_until_unix: 50,
            attempts: 0,
        });
        assert!(q.cancel("q1", 40)); // inside undo window
        q.enqueue(QueuedSend {
            queue_id: "q2".into(),
            request: SendRequest {
                from: "a".into(),
                to: vec!["b".into()],
                message: vec![],
            },
            not_before_unix: 100,
            undo_window_until_unix: 50,
            attempts: 0,
        });
        // Scheduled send: recallable until its dispatch time even though
        // the undo window already closed.
        assert!(q.cancel("q2", 60));
        q.enqueue(QueuedSend {
            queue_id: "q3".into(),
            request: SendRequest {
                from: "a".into(),
                to: vec!["b".into()],
                message: vec![],
            },
            not_before_unix: 100,
            undo_window_until_unix: 50,
            attempts: 0,
        });
        assert!(!q.cancel("q3", 150)); // committed AND past due — dispatcher's
        // Reschedule moves the dispatch time of a pending item.
        assert!(q.reschedule("q3", 500));
        assert!(!q.reschedule("gone", 500));
        assert_eq!(q.due(499).len(), 0);
        assert_eq!(q.due(500).len(), 1);
        assert_eq!(q.pending_count(), 0);
    }

    // ------------------------------------------------------------------
    // Recorded-transcript state-machine tests (in-code fixtures pending
    // Agent 6's T-114 transcript corpus).
    // ------------------------------------------------------------------

    use crate::transport::CertVerdict;
    use tokio::task::JoinHandle;

    /// Spawn a scripted "server". Each step is `(expected_prefix, reply)`:
    /// `None` sends bytes immediately (server-initiated greeting); `Some`
    /// first reads a client line and asserts its prefix before replying.
    fn serve(
        mut end: tokio::io::DuplexStream,
        steps: Vec<(Option<&'static str>, &'static [u8])>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = Vec::new();
            for (expect_prefix, reply) in steps {
                if let Some(p) = expect_prefix {
                    let line = read_line(&mut end, &mut buf, PROTO).await.unwrap();
                    let got = String::from_utf8_lossy(&line);
                    assert!(got.starts_with(p), "expected {p:?}, got {got:?}");
                }
                end.write_all(reply).await.unwrap();
            }
        })
    }

    fn plain_transport(end: tokio::io::DuplexStream) -> Transport {
        Transport::from_stream(
            end,
            "mail.example.test",
            25,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        )
    }

    #[tokio::test]
    async fn greeting_not_220_rejects() {
        let (c, mut s) = duplex(4096);
        let h = tokio::spawn(async move {
            s.write_all(b"554 go away\r\n").await.unwrap();
        });
        let r = SmtpClient::connect(plain_transport(c), SmtpConfig::default()).await;
        assert!(matches!(r, Err(MailError::ServerReject { .. })));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn ehlo_falls_back_to_helo() {
        let (c, s) = duplex(8192);
        let _h = serve(
            s,
            vec![
                (None, b"220 mx\r\n"),
                (Some("EHLO"), b"500 unrecognized\r\n"),
                (Some("HELO"), b"250 mx\r\n"),
                (Some("QUIT"), b"221 bye\r\n"),
            ],
        );
        let mut client = SmtpClient::connect(plain_transport(c), SmtpConfig::default())
            .await
            .unwrap();
        assert!(client.ehlo_info().unwrap().extensions.is_empty());
        client.quit().await.unwrap();
    }

    #[tokio::test]
    async fn multiline_reply_code_mismatch_is_protocol_error() {
        let (c, mut s) = duplex(8192);
        let _h = tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            // inconsistent continuation code — a malformed reply
            s.write_all(b"250-ok so far\r\n451 changed my mind\r\n")
                .await
                .unwrap();
        });
        let r = SmtpClient::connect(plain_transport(c), SmtpConfig::default()).await;
        assert!(matches!(r, Err(MailError::Protocol { .. })));
    }

    #[tokio::test]
    async fn auth_login_two_step() {
        let (c, mut s) = duplex(8192);
        let enc = base64::engine::general_purpose::STANDARD;
        let h = tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // EHLO
            s.write_all(b"250-mx\r\n250 AUTH LOGIN PLAIN\r\n")
                .await
                .unwrap();
            let l = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // AUTH LOGIN
            assert_eq!(l, b"AUTH LOGIN");
            s.write_all(b"334 VXNlcm5hbWU6\r\n").await.unwrap(); // "Username:"
            let l = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // base64(user)
            assert_eq!(l, enc.encode("alice").as_bytes());
            s.write_all(b"334 UGFzc3dvcmQ6\r\n").await.unwrap(); // "Password:"
            let l = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // base64(pass)
            assert_eq!(l, enc.encode("s3cret").as_bytes());
            s.write_all(b"235 2.7.0 authenticated\r\n").await.unwrap();
        });
        let mut client = SmtpClient::connect(
            plain_transport(c),
            SmtpConfig {
                allow_plaintext_auth: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        client
            .authenticate(&SmtpAuth::Login {
                user: "alice".into(),
                password: Zeroizing::new("s3cret".into()),
            })
            .await
            .unwrap();
        h.await.unwrap();
    }

    #[tokio::test]
    async fn auth_failure_maps_to_auth_error() {
        let (c, mut s) = duplex(8192);
        tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // EHLO
            s.write_all(b"250 mx\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // AUTH PLAIN
            s.write_all(b"535 5.7.8 bad credentials\r\n").await.unwrap();
        });
        let mut client = SmtpClient::connect(
            plain_transport(c),
            SmtpConfig {
                allow_plaintext_auth: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let auth = SmtpAuth::Plain {
            user: "u".into(),
            password: Zeroizing::new("wrong".into()),
        };
        match client.authenticate(&auth).await {
            Err(MailError::Auth(detail)) => assert!(detail.contains("535")),
            other => panic!("expected Auth error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn all_recipients_rejected_skips_data_and_rsets() {
        let (c, mut s) = duplex(8192);
        let h = tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // EHLO
            s.write_all(b"250 mx\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // MAIL
            s.write_all(b"250 ok\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // RCPT 1
            s.write_all(b"550 nope\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // RCPT 2
            s.write_all(b"551 nope\r\n").await.unwrap();
            let l = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // must be RSET
            assert_eq!(l, b"RSET");
            s.write_all(b"250 reset\r\n").await.unwrap();
        });
        let mut client = SmtpClient::connect(plain_transport(c), SmtpConfig::default())
            .await
            .unwrap();
        let req = SendRequest {
            from: "me@x.test".into(),
            to: vec!["a@y".into(), "b@y".into()],
            message: b"Subject: x\r\n\r\nhi\r\n".to_vec(),
        };
        let out = client.send_mail(&req).await.unwrap();
        assert!(out.accepted.is_empty());
        assert_eq!(out.rejected.len(), 2);
        assert!(out.data_reply.is_none());
        h.await.unwrap();
    }

    #[tokio::test]
    async fn data_command_rejected() {
        let (c, mut s) = duplex(8192);
        tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250 mx\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250 ok\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250 ok\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap(); // DATA
            s.write_all(b"554 transaction failed\r\n").await.unwrap();
        });
        let mut client = SmtpClient::connect(plain_transport(c), SmtpConfig::default())
            .await
            .unwrap();
        let req = SendRequest {
            from: "me@x.test".into(),
            to: vec!["a@y".into()],
            message: b"Subject: x\r\n\r\nhi\r\n".to_vec(),
        };
        assert!(matches!(
            client.send_mail(&req).await,
            Err(MailError::ServerReject { .. })
        ));
    }

    #[tokio::test]
    async fn size_over_limit_refused_before_sending() {
        let (c, mut s) = duplex(8192);
        tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250-mx\r\n250 SIZE 100\r\n").await.unwrap();
            // server must NOT see MAIL FROM
        });
        let mut client = SmtpClient::connect(plain_transport(c), SmtpConfig::default())
            .await
            .unwrap();
        let req = SendRequest {
            from: "me@x.test".into(),
            to: vec!["a@y".into()],
            message: vec![b'x'; 500],
        };
        assert!(matches!(
            client.send_mail(&req).await,
            Err(MailError::ServerReject { .. })
        ));
    }

    /// Real rustls server over duplex: exercises the STARTTLS upgrade path
    /// end-to-end and asserts the recorded TlsObservation.
    #[tokio::test]
    async fn starttls_upgrade_captures_tls_observation() {
        // Self-signed fixture cert; client trusts it via extra_roots.
        let certified =
            rcgen::generate_simple_self_signed(vec!["mail.example.test".to_string()]).unwrap();
        let cert_der = certified.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();

        let (c, mut s) = duplex(1 << 16);
        tokio::spawn(async move {
            s.write_all(b"220 mx ESMTP\r\n").await.unwrap();
            let mut buf = Vec::new();
            // EHLO (plaintext)
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250-mx\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            // STARTTLS
            let l = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            assert_eq!(l, b"STARTTLS");
            s.write_all(b"220 Go ahead\r\n").await.unwrap();
            // TLS handshake on the same stream
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));
            let mut tls = acceptor.accept(s).await.unwrap();
            // EHLO again (post-TLS)
            let _ = read_line(&mut tls, &mut buf, PROTO).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut tls, b"250-mx\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            // AUTH PLAIN (over TLS now)
            let _ = read_line(&mut tls, &mut buf, PROTO).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut tls, b"235 2.7.0 ok\r\n")
                .await
                .unwrap();
        });

        let settings = TlsSettings {
            accept_invalid_certs: false,
            extra_roots: vec![cert_der.as_ref().to_vec()],
        };
        let t = Transport::from_stream(
            c,
            "mail.example.test",
            587,
            SocketSecurity::StartTls,
            settings,
        );
        let mut client = SmtpClient::connect(t, SmtpConfig::default()).await.unwrap();

        let obs = client.transport().observation().expect("tls observation");
        assert!(obs.upgraded_via_starttls);
        assert_eq!(obs.cert_verdict, Some(CertVerdict::Valid));
        assert!(!obs.peer_certificates.is_empty());
        assert!(obs.cipher_suite.is_some());
        assert!(client.transport().is_encrypted());

        // Plaintext-auth gate must now pass (transport is encrypted).
        let auth = SmtpAuth::Plain {
            user: "u".into(),
            password: Zeroizing::new("p".into()),
        };
        client.authenticate(&auth).await.unwrap();
    }

    /// Same upgrade but with an untrusted cert: `accept_invalid_certs`
    /// completes the handshake while the real verdict is still recorded.
    #[tokio::test]
    async fn starttls_records_invalid_verdict_when_accepted_for_test() {
        // CA-signed leaf for "other.test"; client trusts the CA, so chain
        // verification succeeds and the failure lands on the hostname check.
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec!["kiwi-test-ca".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["other.test".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        let leaf_der = leaf_cert.der().clone();
        let leaf_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der], leaf_key_der)
            .unwrap();
        let ca_der = ca_cert.der().to_vec();

        let (c, mut s) = duplex(1 << 16);
        tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250-mx\r\n250 STARTTLS\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"220 go\r\n").await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));
            let mut tls = acceptor.accept(s).await.unwrap();
            let _ = read_line(&mut tls, &mut buf, PROTO).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut tls, b"250 mx\r\n")
                .await
                .unwrap();
        });

        // Hostname mismatch: cert is for "other.test", we connect as
        // "mail.example.test" — verdict must be HostnameMismatch.
        let settings = TlsSettings {
            accept_invalid_certs: true,
            extra_roots: vec![ca_der],
        };
        let t = Transport::from_stream(
            c,
            "mail.example.test",
            587,
            SocketSecurity::StartTls,
            settings,
        );
        let client = SmtpClient::connect(t, SmtpConfig::default()).await.unwrap();
        let obs = client.transport().observation().unwrap();
        assert!(obs.upgraded_via_starttls);
        assert_eq!(obs.cert_verdict, Some(CertVerdict::HostnameMismatch));
    }

    /// Strict default: invalid cert without the test hatch must fail.
    #[tokio::test]
    async fn starttls_invalid_cert_rejected_by_default() {
        let certified = rcgen::generate_simple_self_signed(vec!["other.test".to_string()]).unwrap();
        let cert_der = certified.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

        let (c, mut s) = duplex(1 << 16);
        tokio::spawn(async move {
            s.write_all(b"220 mx\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"250-mx\r\n250 STARTTLS\r\n").await.unwrap();
            let _ = read_line(&mut s, &mut buf, PROTO).await.unwrap();
            s.write_all(b"220 go\r\n").await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));
            let _ = acceptor.accept(s).await; // will fail client-side; ignore
        });

        let t = Transport::from_stream(
            c,
            "mail.example.test",
            587,
            SocketSecurity::StartTls,
            TlsSettings::default(), // strict
        );
        let r = SmtpClient::connect(t, SmtpConfig::default()).await;
        assert!(matches!(r, Err(MailError::Tls(_))));
    }
}
