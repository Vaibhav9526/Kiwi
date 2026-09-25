//! SMTP client — `impl SmtpClient`: greeting/EHLO/STARTTLS/AUTH +
//! MAIL/RCPT/DATA send flow, plus the reply reader. Command-string
//! helpers and the send queue live in `commands.rs`.

use std::collections::BTreeMap;

use base64::Engine;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::error::{MailError, Result};
use crate::lines::{read_line, write_line};
use crate::transport::{SocketSecurity, Transport};

use super::*;

impl SmtpClient {
    /// Connect: read the 220 greeting, EHLO, perform STARTTLS when required
    /// by `Transport`'s socket security, then EHLO again post-upgrade.
    pub async fn connect(t: Transport, config: SmtpConfig) -> Result<Self> {
        let mut c = Self {
            t,
            config,
            ehlo: None,
            scratch: Vec::new(),
        };
        let greeting = c.read_reply().await?;
        if greeting.code != 220 {
            return Err(MailError::ServerReject {
                command: "connect".into(),
                reply: greeting.message(),
            });
        }
        c.ehlo().await?;
        Ok(c)
    }

    /// The EHLO state after any STARTTLS upgrade — what the *current*
    /// encrypted session actually supports.
    pub fn ehlo_info(&self) -> Option<&EhloInfo> {
        self.ehlo.as_ref()
    }

    pub fn transport(&self) -> &Transport {
        &self.t
    }

    async fn command(&mut self, line: &str) -> Result<SmtpReply> {
        write_line(&mut self.t, line.as_bytes()).await?;
        self.read_reply().await
    }

    async fn read_reply(&mut self) -> Result<SmtpReply> {
        tokio::time::timeout(CMD_TIMEOUT, self.read_reply_inner())
            .await
            .map_err(|_| {
                MailError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "smtp reply timeout",
                ))
            })?
    }

    async fn read_reply_inner(&mut self) -> Result<SmtpReply> {
        let mut code: Option<u16> = None;
        let mut lines = Vec::new();
        loop {
            let raw = read_line(&mut self.t, &mut self.scratch, PROTO).await?;
            if raw.len() < 4 {
                return Err(MailError::Protocol {
                    protocol: PROTO,
                    detail: format!("malformed reply line: {}", String::from_utf8_lossy(&raw)),
                });
            }
            let parsed: u16 = raw[..3]
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .fold(0u16, |a, b| a * 10 + (b - b'0') as u16);
            if raw[..3].iter().any(|b| !b.is_ascii_digit()) {
                return Err(MailError::Protocol {
                    protocol: PROTO,
                    detail: format!("non-numeric reply code: {}", String::from_utf8_lossy(&raw)),
                });
            }
            match code {
                None => code = Some(parsed),
                // Multiline replies must keep one code (RFC 5321 §4.2.1).
                Some(c) if c != parsed => {
                    return Err(MailError::Protocol {
                        protocol: PROTO,
                        detail: "multiline reply with inconsistent codes".into(),
                    });
                }
                _ => {}
            }
            let sep = raw[3];
            let text = String::from_utf8_lossy(&raw[4.min(raw.len())..]).into_owned();
            lines.push(text);
            if sep == b' ' {
                break;
            }
            if sep != b'-' || lines.len() >= MAX_REPLY_LINES {
                return Err(MailError::Protocol {
                    protocol: PROTO,
                    detail: "malformed/overflowing multiline reply".into(),
                });
            }
        }
        let enhanced = lines
            .first()
            .and_then(|l| l.split_whitespace().next())
            .filter(|tok| {
                tok.len() >= 5
                    && tok.bytes().next().is_some_and(|b| b.is_ascii_digit())
                    && tok.contains('.')
            })
            .map(str::to_owned);
        Ok(SmtpReply {
            code: code.unwrap_or(0),
            lines,
            enhanced,
        })
    }

    async fn ehlo(&mut self) -> Result<()> {
        let name = self.config.client_name.clone();
        let reply = self.command(&format!("EHLO {name}")).await?;
        if !reply.is_success() {
            // RFC 5321 fallback for ancient servers.
            let r = self.command(&format!("HELO {name}")).await?;
            if !r.is_success() {
                return Err(MailError::ServerReject {
                    command: "EHLO/HELO".into(),
                    reply: r.message(),
                });
            }
            self.ehlo = Some(EhloInfo {
                greeting: r.message(),
                extensions: BTreeMap::new(),
            });
            return Ok(());
        }
        self.ehlo = Some(parse_ehlo_reply(&reply));

        if self.t_socket_security() == SocketSecurity::StartTls {
            if self.ehlo.as_ref().is_some_and(|e| e.has_starttls()) {
                self.command("STARTTLS").await.and_then(|r| {
                    if r.code == 220 {
                        Ok(())
                    } else {
                        Err(MailError::ServerReject {
                            command: "STARTTLS".into(),
                            reply: r.message(),
                        })
                    }
                })?;
                self.t.starttls_upgrade().await?;
                // RFC 3207 §4.2: fresh EHLO over the TLS session —
                // extensions may differ from the plaintext advertisement.
                let name = self.config.client_name.clone();
                let r = self.command(&format!("EHLO {name}")).await?;
                if !r.is_success() {
                    return Err(MailError::ServerReject {
                        command: "EHLO (post-STARTTLS)".into(),
                        reply: r.message(),
                    });
                }
                self.ehlo = Some(parse_ehlo_reply(&r));
            } else if self.config.require_starttls {
                return Err(MailError::Protocol {
                    protocol: PROTO,
                    detail: "server does not advertise STARTTLS; connection refused \
                             (require_starttls). Possible downgrade attempt."
                        .into(),
                });
            }
        }
        Ok(())
    }

    fn t_socket_security(&self) -> SocketSecurity {
        // Transport keeps its configured mode; live encryption state is in
        // `observation`. STARTTLS mode upgrades on demand.
        self.t.socket_security()
    }

    /// Authenticate per `auth`. Refuses cleartext credentials unless the
    /// caller explicitly opted in via `allow_plaintext_auth`.
    pub async fn authenticate(&mut self, auth: &SmtpAuth) -> Result<()> {
        let needs_secret = !matches!(auth, SmtpAuth::None);
        if needs_secret && !self.t.is_encrypted() && !self.config.allow_plaintext_auth {
            return Err(MailError::Protocol {
                protocol: PROTO,
                detail: "refusing to send credentials over plaintext \
                         (allow_plaintext_auth is off)"
                    .into(),
            });
        }
        match auth {
            SmtpAuth::None => Ok(()),
            SmtpAuth::Plain { user, password } => {
                let token = base64::engine::general_purpose::STANDARD
                    .encode(Zeroizing::new(format!("\0{user}\0{}", password.as_str())));
                let r = self.command(&format!("AUTH PLAIN {token}")).await?;
                auth_result(r)
            }
            SmtpAuth::Login { user, password } => {
                let r = self.command("AUTH LOGIN").await?;
                if r.code != 334 {
                    return auth_result(r);
                }
                let enc = base64::engine::general_purpose::STANDARD;
                let r = self.command(&enc.encode(user.as_bytes())).await?;
                if r.code != 334 {
                    return auth_result(r);
                }
                let r = self
                    .command(
                        &enc.encode(
                            Zeroizing::new(password.as_str().as_bytes().to_vec()).as_slice(),
                        ),
                    )
                    .await?;
                auth_result(r)
            }
            SmtpAuth::XOAuth2 { user, token } => {
                let sasl = Zeroizing::new(format!(
                    "user={user}\x01auth=Bearer {}\x01\x01",
                    token.as_str()
                ));
                let b64 = base64::engine::general_purpose::STANDARD.encode(sasl.as_bytes());
                let r = self.command(&format!("AUTH XOAUTH2 {b64}")).await?;
                auth_result(r)
            }
        }
    }

    /// Send one message. Envelope addresses are validated; body bytes are
    /// dot-stuffed on the wire. Partial recipient rejection is reported in
    /// `SendOutcome.rejected` (not an error) — hard failures return `Err`.
    pub async fn send_mail(&mut self, req: &SendRequest) -> Result<SendOutcome> {
        validate_envelope(&req.from, &req.to)?;

        if let Some(max) = self.ehlo.as_ref().and_then(|e| e.max_size())
            && req.message.len() as u64 > max
        {
            return Err(MailError::ServerReject {
                command: "MAIL".into(),
                reply: format!(
                    "message {} bytes exceeds server SIZE {max}",
                    req.message.len()
                ),
            });
        }

        let size = req.message.len();
        // SIZE parameter is only legal when the server advertised it (RFC 1870).
        let mail_from = if self.ehlo.as_ref().is_some_and(|e| e.supports("SIZE")) {
            format!("MAIL FROM:<{}> SIZE={size}", req.from)
        } else {
            format!("MAIL FROM:<{}>", req.from)
        };
        let r = self.command(&mail_from).await?;
        if !r.is_success() {
            return Err(MailError::ServerReject {
                command: "MAIL FROM".into(),
                reply: r.message(),
            });
        }

        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for rcpt in &req.to {
            let r = self.command(&format!("RCPT TO:<{rcpt}>")).await?;
            if r.is_success() {
                accepted.push(rcpt.clone());
            } else {
                rejected.push((rcpt.clone(), r));
            }
        }
        if accepted.is_empty() {
            let _ = self.command("RSET").await;
            return Ok(SendOutcome {
                accepted,
                rejected,
                data_reply: None,
            });
        }

        let r = self.command("DATA").await?;
        if r.code != 354 {
            return Err(MailError::ServerReject {
                command: "DATA".into(),
                reply: r.message(),
            });
        }

        self.t.write_all(&dot_stuff(&req.message)).await?;
        // DATA terminator is <CRLF>.<CRLF>; if the message already ends in
        // CRLF, only the dot line remains to send.
        if req.message.ends_with(b"\r\n") {
            self.t.write_all(b".\r\n").await?;
        } else {
            self.t.write_all(b"\r\n.\r\n").await?;
        }
        self.t.flush().await?;

        let reply = tokio::time::timeout(DATA_TIMEOUT, self.read_reply_inner())
            .await
            .map_err(|_| {
                MailError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "smtp DATA timeout",
                ))
            })??;
        if !reply.is_success() {
            return Err(MailError::ServerReject {
                command: "DATA body".into(),
                reply: reply.message(),
            });
        }
        Ok(SendOutcome {
            accepted,
            rejected,
            data_reply: Some(reply),
        })
    }

    pub async fn noop(&mut self) -> Result<()> {
        let r = self.command("NOOP").await?;
        r.is_success()
            .then_some(())
            .ok_or_else(|| MailError::ServerReject {
                command: "NOOP".into(),
                reply: r.message(),
            })
    }

    /// Reset the current mail transaction (used by undo-send paths).
    pub async fn rset(&mut self) -> Result<()> {
        let r = self.command("RSET").await?;
        r.is_success()
            .then_some(())
            .ok_or_else(|| MailError::ServerReject {
                command: "RSET".into(),
                reply: r.message(),
            })
    }

    pub async fn quit(&mut self) -> Result<()> {
        let _ = self.command("QUIT").await;
        Ok(())
    }

    // Socket-security getter kept as a method so `ehlo()` stays readable.
    // (field is private to transport; mirrored here at connect time)
}
