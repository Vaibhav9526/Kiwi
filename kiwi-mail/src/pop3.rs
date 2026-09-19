//! POP3 receive client (RFC 1939 + CAPA/STLS/UIDL extensions).
//!
//! Same security posture as `smtp`: `SocketSecurity::StartTls` requires the
//! server to advertise STLS in CAPA (fail closed); password auth over
//! plaintext is refused unless the caller explicitly opts in.
//!
//! APOP is legacy challenge-response (MD5 digest of the greeting banner +
//! password). MD5 here is an interop requirement of RFC 1939 §7, not a new
//! cryptographic choice — and it's still never sent unencrypted.

use std::collections::BTreeSet;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{MailError, Result};
use crate::lines::{read_dot_block, read_line, write_line};
use crate::transport::{SocketSecurity, Transport};

const PROTO: &str = "pop3";
const CMD_TIMEOUT: Duration = Duration::from_secs(120);
/// Bound on RETR payloads.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Pop3Config {
    /// Refuse when STLS isn't advertised on a StartTls socket. Default true.
    pub require_stls: bool,
    /// Explicit opt-in for USER/PASS or APOP over plaintext. Default false.
    pub allow_plaintext_auth: bool,
}

impl Default for Pop3Config {
    fn default() -> Self {
        Self {
            require_stls: true,
            allow_plaintext_auth: false,
        }
    }
}

pub enum Pop3Auth {
    /// USER + PASS (two commands).
    UserPass {
        user: String,
        password: Zeroizing<String>,
    },
    /// APOP (RFC 1939 §7): MD5(banner_timestamp + password). Requires the
    /// greeting to have carried a `<…>` timestamp.
    Apop {
        user: String,
        password: Zeroizing<String>,
    },
}

pub struct Pop3Client {
    t: Transport,
    config: Pop3Config,
    capabilities: BTreeSet<String>,
    /// `<…>` banner token from the greeting, for APOP.
    apop_banner: Option<String>,
    scratch: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MessageStat {
    pub number: u32,
    pub octets: u64,
    /// UIDL when fetched separately.
    pub uidl: Option<String>,
}

impl Pop3Client {
    /// Connect: consume `+OK` greeting, run CAPA (tolerating servers that
    /// lack it), and STLS-upgrade when the socket requires it.
    pub async fn connect(t: Transport, config: Pop3Config) -> Result<Self> {
        let mut c = Self {
            t,
            config,
            capabilities: BTreeSet::new(),
            apop_banner: None,
            scratch: Vec::new(),
        };
        let line = c.read_status().await?;
        if !line.starts_with("+OK") {
            return Err(MailError::ServerReject {
                command: "connect".into(),
                reply: line,
            });
        }
        c.apop_banner = extract_banner(&line);
        let _ = c.capa().await; // CAPA is optional on old servers
        if c.t.socket_security() == SocketSecurity::StartTls {
            if c.has_capa("STLS") {
                c.stls().await?;
            } else if c.config.require_stls {
                return Err(MailError::Protocol {
                    protocol: PROTO,
                    detail: "server does not advertise STLS; connection refused \
                             (possible downgrade attempt)"
                        .into(),
                });
            }
        }
        Ok(c)
    }

    pub fn has_capa(&self, cap: &str) -> bool {
        self.capabilities.contains(&cap.to_ascii_uppercase())
    }

    pub fn capabilities(&self) -> &BTreeSet<String> {
        &self.capabilities
    }

    pub fn transport(&self) -> &Transport {
        &self.t
    }

    /// `+OK …` / `-ERR …` single-line status.
    async fn read_status(&mut self) -> Result<String> {
        let raw = tokio::time::timeout(
            CMD_TIMEOUT,
            read_line(&mut self.t, &mut self.scratch, PROTO),
        )
        .await
        .map_err(|_| {
            MailError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "pop3 timeout",
            ))
        })??;
        Ok(String::from_utf8_lossy(&raw).into_owned())
    }

    /// Command expecting a `+OK` status; returns the status text.
    async fn ok_command(&mut self, cmd: &str) -> Result<String> {
        write_line(&mut self.t, cmd.as_bytes()).await?;
        let status = self.read_status().await?;
        if !status.starts_with("+OK") {
            return Err(MailError::ServerReject {
                command: cmd.split_whitespace().next().unwrap_or(cmd).into(),
                reply: status,
            });
        }
        Ok(status)
    }

    /// Command returning a dot-terminated multiline body.
    async fn multiline_command(&mut self, cmd: &str) -> Result<Vec<String>> {
        write_line(&mut self.t, cmd.as_bytes()).await?;
        let status = self.read_status().await?;
        if !status.starts_with("+OK") {
            return Err(MailError::ServerReject {
                command: cmd.into(),
                reply: status,
            });
        }
        let block = read_dot_block(&mut self.t, PROTO, MAX_MESSAGE).await?;
        let text = String::from_utf8_lossy(&block).into_owned();
        Ok(text
            .split("\r\n")
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// CAPA → capability tokens (first word of each line, uppercased).
    async fn capa(&mut self) -> Result<()> {
        write_line(&mut self.t, b"CAPA").await?;
        let status = self.read_status().await?;
        if !status.starts_with("+OK") {
            return Ok(()); // old servers may not support CAPA
        }
        let block = read_dot_block(&mut self.t, PROTO, 1 << 20).await?;
        let text = String::from_utf8_lossy(&block);
        for line in text.split("\r\n") {
            if let Some(tok) = line.split_whitespace().next()
                && !tok.is_empty()
            {
                self.capabilities.insert(tok.to_ascii_uppercase());
            }
        }
        Ok(())
    }

    async fn stls(&mut self) -> Result<()> {
        self.ok_command("STLS").await?;
        self.t.starttls_upgrade().await?;
        // Capabilities may change post-TLS; refresh, tolerate failure.
        let _ = self.capa().await;
        Ok(())
    }

    /// Authenticate. Plaintext auth requires explicit `allow_plaintext_auth`.
    pub async fn authenticate(&mut self, auth: &Pop3Auth) -> Result<()> {
        if !self.t.is_encrypted() && !self.config.allow_plaintext_auth {
            return Err(MailError::Protocol {
                protocol: PROTO,
                detail: "refusing to send credentials over plaintext \
                         (allow_plaintext_auth is off)"
                    .into(),
            });
        }
        match auth {
            Pop3Auth::UserPass { user, password } => {
                check_param(PROTO, "USER", user)?;
                self.ok_command(&format!("USER {user}")).await?;
                check_param(PROTO, "PASS", password.as_str())?;
                self.ok_command(&format!("PASS {}", password.as_str()))
                    .await?;
            }
            Pop3Auth::Apop { user, password } => {
                check_param(PROTO, "APOP", user)?;
                let banner = self
                    .apop_banner
                    .clone()
                    .ok_or_else(|| MailError::Protocol {
                        protocol: PROTO,
                        detail: "server greeting carried no APOP timestamp".into(),
                    })?;
                // Legacy interop only — RFC 1939 §7 mandates MD5 here.
                let digest = md5::compute(format!("{banner}{}", password.as_str()));
                self.ok_command(&format!("APOP {user} {:x}", digest))
                    .await?;
            }
        }
        Ok(())
    }

    /// STAT → (message count, total octets).
    pub async fn stat(&mut self) -> Result<(u64, u64)> {
        let status = self.ok_command("STAT").await?;
        let mut it = status.split_whitespace();
        let _ = it.next(); // "+OK"
        let count = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let octets = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        Ok((count, octets))
    }

    /// LIST → per-message (number, octets).
    pub async fn list(&mut self) -> Result<Vec<MessageStat>> {
        let lines = self.multiline_command("LIST").await?;
        Ok(lines
            .iter()
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                Some(MessageStat {
                    number: it.next()?.parse().ok()?,
                    octets: it.next()?.parse().ok()?,
                    uidl: None,
                })
            })
            .collect())
    }

    /// UIDL → (number → uidl) pairs for stable identity across sessions.
    pub async fn uidl(&mut self) -> Result<Vec<(u32, String)>> {
        let lines = self.multiline_command("UIDL").await?;
        Ok(lines
            .iter()
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                Some((it.next()?.parse().ok()?, it.next()?.to_string()))
            })
            .collect())
    }

    /// RETR n → raw RFC 5322 message bytes (dot-stuffing undone).
    pub async fn retr(&mut self, number: u32) -> Result<Vec<u8>> {
        write_line(&mut self.t, format!("RETR {number}").as_bytes()).await?;
        let status = self.read_status().await?;
        if !status.starts_with("+OK") {
            return Err(MailError::ServerReject {
                command: "RETR".into(),
                reply: status,
            });
        }
        read_dot_block(&mut self.t, PROTO, MAX_MESSAGE).await
    }

    /// TOP n lines → headers + first `lines` body lines.
    pub async fn top(&mut self, number: u32, lines: u32) -> Result<Vec<u8>> {
        write_line(&mut self.t, format!("TOP {number} {lines}").as_bytes()).await?;
        let status = self.read_status().await?;
        if !status.starts_with("+OK") {
            return Err(MailError::ServerReject {
                command: "TOP".into(),
                reply: status,
            });
        }
        read_dot_block(&mut self.t, PROTO, MAX_MESSAGE).await
    }

    pub async fn dele(&mut self, number: u32) -> Result<()> {
        self.ok_command(&format!("DELE {number}")).await?;
        Ok(())
    }

    pub async fn rset(&mut self) -> Result<()> {
        self.ok_command("RSET").await?;
        Ok(())
    }

    pub async fn noop(&mut self) -> Result<()> {
        self.ok_command("NOOP").await?;
        Ok(())
    }

    /// QUIT commits pending DELEs on the server side.
    pub async fn quit(&mut self) -> Result<()> {
        let _ = self.ok_command("QUIT").await;
        Ok(())
    }
}

/// Reject CRLF injection in command parameters.
fn check_param(protocol: &'static str, name: &str, value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b < 0x20 && b != b'\t')
    {
        return Err(MailError::Protocol {
            protocol,
            detail: format!("invalid character in {name} parameter"),
        });
    }
    Ok(())
}

/// Extract the `<…>` APOP timestamp from a `+OK` greeting.
fn extract_banner(greeting: &str) -> Option<String> {
    let start = greeting.find('<')?;
    let end = greeting[start..].find('>')? + start;
    Some(greeting[start..=end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TlsSettings;
    use tokio::io::AsyncWriteExt;
    use tokio::io::duplex;

    #[test]
    fn banner_extract() {
        assert_eq!(
            extract_banner("+OK POP3 ready <1896.6971@mail.test>").as_deref(),
            Some("<1896.6971@mail.test>")
        );
        assert_eq!(extract_banner("+OK no banner"), None);
    }

    #[tokio::test]
    async fn userpass_list_retr_flow() {
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            server_end
                .write_all(b"+OK POP3 ready <t@x>\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            // CAPA (client sends it right after the greeting)
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"-ERR no capa\r\n").await.unwrap();
            // USER
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"+OK user\r\n").await.unwrap();
            // PASS
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"+OK locked\r\n").await.unwrap();
            // LIST
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end
                .write_all(b"+OK\r\n1 500\r\n2 900\r\n.\r\n")
                .await
                .unwrap();
            // RETR 2
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end
                .write_all(b"+OK 900 octets\r\nSubject: hi\r\n\r\n..stuffed\r\n.\r\n")
                .await
                .unwrap();
        });
        let mut c = Pop3Client::connect(
            client_end.into_client_transport(),
            Pop3Config {
                allow_plaintext_auth: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        c.authenticate(&Pop3Auth::UserPass {
            user: "u".into(),
            password: Zeroizing::new("p".into()),
        })
        .await
        .unwrap();
        let list = c.list().await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].number, 2);
        let msg = c.retr(2).await.unwrap();
        assert!(msg.starts_with(b"Subject: hi"));
        assert!(String::from_utf8_lossy(&msg).contains(".stuffed"));
    }

    // helper to keep tests readable
    trait IntoClientTransport {
        fn into_client_transport(self) -> Transport;
    }
    impl IntoClientTransport for tokio::io::DuplexStream {
        fn into_client_transport(self) -> Transport {
            Transport::from_stream(
                self,
                "pop.example.test",
                110,
                SocketSecurity::Plaintext,
                TlsSettings::default(),
            )
        }
    }

    #[tokio::test]
    async fn apop_uses_banner_digest() {
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            server_end
                .write_all(b"+OK POP3 ready <1896.6971@mail.test>\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            // CAPA fails gracefully
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end.write_all(b"-ERR no capa\r\n").await.unwrap();
            // APOP — verify digest = md5("<1896.6971@mail.test>" + "secret")
            let line = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            let expect = format!(
                "APOP user {:x}",
                md5::compute("<1896.6971@mail.test>secret")
            );
            assert_eq!(line, expect.as_bytes());
            server_end
                .write_all(b"+OK maildrop has 1 message\r\n")
                .await
                .unwrap();
        });
        let mut c = Pop3Client::connect(
            client_end.into_client_transport(),
            Pop3Config {
                allow_plaintext_auth: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        c.authenticate(&Pop3Auth::Apop {
            user: "user".into(),
            password: Zeroizing::new("secret".into()),
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn plaintext_auth_refused_by_default() {
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            server_end.write_all(b"+OK ready\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap(); // CAPA
            server_end.write_all(b"-ERR\r\n").await.unwrap();
        });
        let mut c = Pop3Client::connect(
            client_end.into_client_transport(),
            Pop3Config::default(), // allow_plaintext_auth = false
        )
        .await
        .unwrap();
        assert!(matches!(
            c.authenticate(&Pop3Auth::UserPass {
                user: "u".into(),
                password: Zeroizing::new("p".into()),
            })
            .await,
            Err(MailError::Protocol { .. })
        ));
    }
}
