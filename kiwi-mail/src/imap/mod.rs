//! IMAP4rev1 receive client (RFC 3501, plus UIDPLUS/MOVE where advertised).
//!
//! Structure: `ImapClient` owns a `Transport`; commands are tagged
//! (`A0001 …`), responses are classified untagged (`*`), continuation (`+`),
//! or tagged completion. Protocol data is parsed through a bounded
//! S-expression layer (`sexp`) — server output is untrusted input.
//!
//! Sync primitives (`select`, `uid_fetch`, `uid_search`, `status`) expose the
//! UIDVALIDITY/UIDNEXT facts `sync.rs` needs; IDLE is a bounded wait that
//! collects untagged change notifications.

use std::collections::BTreeSet;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::transport::Transport;

const PROTO: &str = "imap";
const CMD_TIMEOUT: Duration = Duration::from_secs(120);
/// RFC 3501 allows literals; we bound each response buffer.
const MAX_RESPONSE: usize = 64 * 1024 * 1024;
/// Cap on untagged `* ` lines collected per command — a hostile or broken
/// server could otherwise flood memory between command and tagged reply.
const MAX_UNTAGGED: usize = 8192;
/// Cap on IDLE-collected notifications per idle cycle.
const MAX_IDLE_EVENTS: usize = 4096;

mod commands;
mod parser;

pub use parser::*;

pub struct ImapClient {
    t: Transport,
    config: ImapConfig,
    tag_counter: u32,
    capabilities: BTreeSet<String>,
    scratch: Vec<u8>,
}

/// Client policy. Plaintext auth is refused unless explicitly opted in —
/// same posture as `SmtpConfig`/`Pop3Config`.
#[derive(Debug, Clone, Default)]
pub struct ImapConfig {
    /// Allow LOGIN/AUTHENTICATE over an unencrypted transport. Default false.
    pub allow_plaintext_auth: bool,
}

/// Login/authenticate credential forms. Secrets are zeroizing.
pub enum ImapAuth {
    Login {
        user: String,
        password: Zeroizing<String>,
    },
    /// AUTHENTICATE XOAUTH2 (works with/without SASL-IR).
    XOAuth2 {
        user: String,
        token: Zeroizing<String>,
    },
    /// AUTHENTICATE PLAIN.
    Plain {
        user: String,
        password: Zeroizing<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MailError;
    use crate::lines::read_line;
    use crate::transport::{SocketSecurity, TlsSettings};
    use tokio::io::{AsyncWriteExt, duplex};

    #[test]
    fn sexp_parses_lists_strings_literals() {
        let s = parse_sexp(b"(FLAGS (\\Seen \\Deleted) UID 42 SUBJECT \"hi \\\"x\\\"\")").unwrap();
        let SExp::List(items) = s else {
            panic!("not list")
        };
        assert_eq!(items[0].as_str().unwrap(), "FLAGS");
    }

    #[test]
    fn sexp_handles_literal() {
        let s = parse_sexp(b"(BODY[] {5}\r\nhello UID 9)").unwrap();
        let SExp::List(items) = s else {
            panic!("not list")
        };
        assert_eq!(items[1], SExp::Str(b"hello".to_vec()));
        assert_eq!(items[2].as_str().unwrap(), "UID");
        assert_eq!(items[3].as_u64(), Some(9));
    }

    #[test]
    fn sexp_rejects_malformed() {
        assert!(parse_sexp(b"(unterminated").is_err());
        assert!(parse_sexp(b"\"unterminated").is_err());
    }

    #[test]
    fn envelope_parses() {
        let raw = b"FETCH (ENVELOPE (\"Wed, 17 Sep 2025 10:00:00 +0000\" \"hello subj\" ((\"Alice\" NIL \"alice\" \"x.test\")) NIL NIL ((NIL NIL \"bob\" \"y.test\")) NIL NIL \"<r@x>\" \"<m@x>\"))";
        let s = parse_sexp(&raw[6..]).unwrap();
        let env = parse_envelope(&s.as_list().unwrap()[1]).unwrap();
        assert_eq!(env.subject.as_deref(), Some("hello subj"));
        assert_eq!(env.from[0].email, "alice@x.test");
        assert_eq!(env.from[0].name.as_deref(), Some("Alice"));
        assert_eq!(env.to[0].email, "bob@y.test");
        assert_eq!(env.message_id.as_deref(), Some("<m@x>"));
    }

    #[test]
    fn bodystructure_multipart() {
        let raw = b"((\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 100 2)(\"text\" \"html\" NIL NIL NIL \"8bit\" 200 3) \"alternative\" (\"boundary\" \"b1\"))";
        let s = parse_sexp(raw).unwrap();
        match parse_bodystructure(&s) {
            BodyStructure::Multi { subtype, parts, .. } => {
                assert_eq!(subtype, "alternative");
                assert_eq!(parts.len(), 2);
            }
            other => panic!("expected multipart, got {other:?}"),
        }
    }

    #[test]
    fn fetch_line_parses() {
        let line = b"23 FETCH (UID 1001 FLAGS (\\Seen) RFC822.SIZE 1234 INTERNALDATE \"17-Sep-2025 10:00:00 +0000\" ENVELOPE (\"d\" \"s\" ((\"A\" NIL \"a\" \"x.test\")) NIL NIL NIL NIL NIL \"<r>\" \"<m>\"))";
        let item = parse_fetch_line(line).unwrap().unwrap();
        assert_eq!(item.seq, 23);
        assert_eq!(item.uid, Some(1001));
        assert_eq!(item.flags, vec!["\\Seen"]);
        assert_eq!(item.size, Some(1234));
        assert_eq!(item.envelope.unwrap().message_id.as_deref(), Some("<m>"));
    }

    #[tokio::test]
    async fn connect_capability_select_flow() {
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            server_end.write_all(b"* OK imap ready\r\n").await.unwrap();
            let mut buf = Vec::new();
            // CAPABILITY
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end
                .write_all(
                    b"* CAPABILITY IMAP4rev1 UIDPLUS IDLE MOVE LITERAL+\r\nA0001 OK done\r\n",
                )
                .await
                .unwrap();
            // SELECT
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap();
            server_end
                .write_all(
                    b"* FLAGS (\\Seen \\Deleted)\r\n* 3 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 777] uids\r\n* OK [UIDNEXT 1004] next\r\nA0002 OK [READ-WRITE] selected\r\n",
                )
                .await
                .unwrap();
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext, // plaintext socket: connect skips STLS
            TlsSettings::default(),
        );
        let mut c = ImapClient::connect(t).await.unwrap();
        assert!(c.has_capability("UIDPLUS"));
        assert!(c.has_capability("IDLE"));
        let sel = c.select("INBOX", false).await.unwrap();
        assert_eq!(sel.exists, 3);
        assert_eq!(sel.uid_validity, Some(777));
        assert_eq!(sel.uid_next, Some(1004));
        assert_eq!(sel.flags, vec!["\\Seen", "\\Deleted"]);
        assert!(!sel.read_only);
    }

    #[test]
    fn tagged_match_requires_space() {
        assert!(is_tagged(b"A0001 OK done", "A0001"));
        assert!(!is_tagged(b"A00010 OK sneaky", "A0001"));
        assert!(!is_tagged(b"A0001", "A0001"));
    }

    #[test]
    fn command_args_reject_ctl() {
        assert!(check_quoted("INBOX\r\nA9 NOOP").is_err());
        assert!(check_quoted("Normal Box").is_ok());
        assert!(check_bare("1,2:*").is_ok());
        assert!(check_bare("1 2").is_err());
        assert!(check_bare("").is_err());
        assert!(check_tail("UNSEEN SINCE 1-Feb-1994").is_ok());
        assert!(check_tail("ALL\r\nLOGOUT").is_err());
    }

    #[tokio::test]
    async fn connect_rejects_bye_greeting() {
        let (client_end, mut server_end) = duplex(1 << 16);
        let h = tokio::spawn(async move {
            let _ = server_end
                .write_all(b"* BYE server is shutting down\r\n")
                .await;
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        );
        let r = ImapClient::connect(t).await;
        assert!(matches!(r, Err(MailError::ServerReject { .. })));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn connect_accepts_preauth() {
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            let _ = server_end.write_all(b"* PREAUTH logged in\r\n").await;
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await;
            let _ = server_end
                .write_all(b"* CAPABILITY IMAP4rev1\r\nA0001 OK\r\n")
                .await;
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        );
        let c = ImapClient::connect(t).await.unwrap();
        assert!(c.has_capability("IMAP4rev1"));
    }

    /// Two literals each under the per-literal bound but over the aggregate
    /// response bound — the second must be rejected before allocation.
    #[tokio::test]
    async fn aggregate_literal_bound() {
        const BIG: usize = 60 * 1024 * 1024;
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            let _ = server_end.write_all(b"* OK ready\r\n").await;
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await; // CAPABILITY
            let _ = server_end
                .write_all(b"* CAPABILITY IMAP4rev1\r\nA0001 OK\r\n")
                .await;
            let _ = read_line(&mut server_end, &mut buf, PROTO).await; // UID FETCH
            let _ = server_end
                .write_all(format!("* 1 FETCH (BODY[] {{{BIG}}}\r\n").as_bytes())
                .await;
            let _ = server_end.write_all(&vec![b'x'; BIG]).await;
            let _ = server_end
                .write_all(b" UID 1 {20000000}\r\nA0002 OK\r\n")
                .await;
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        );
        let mut c = ImapClient::connect(t).await.unwrap();
        let r = c.uid_fetch("1", &["UID", "BODY[]"]).await;
        assert!(matches!(r, Err(MailError::Protocol { .. })));
    }

    /// CRLF inside a mailbox name must be rejected before anything is sent.
    #[tokio::test]
    async fn select_injection_rejected() {
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            let _ = server_end.write_all(b"* OK ready\r\n").await;
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await;
            let _ = server_end
                .write_all(b"* CAPABILITY IMAP4rev1\r\nA0001 OK\r\n")
                .await;
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        );
        let mut c = ImapClient::connect(t).await.unwrap();
        assert!(matches!(
            c.select("INBOX\r\nA9 NOOP", false).await,
            Err(MailError::Protocol { .. })
        ));
        assert!(matches!(
            c.uid_search("ALL\r\nA9 LOGOUT").await,
            Err(MailError::Protocol { .. })
        ));
    }

    #[tokio::test]
    async fn uid_search_parses_uids() {
        let (client_end, mut server_end) = duplex(1 << 16);
        tokio::spawn(async move {
            server_end.write_all(b"* OK ready\r\n").await.unwrap();
            let mut buf = Vec::new();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap(); // CAPABILITY
            server_end
                .write_all(b"* CAPABILITY IMAP4rev1 UIDPLUS\r\nA0001 OK\r\n")
                .await
                .unwrap();
            let _ = read_line(&mut server_end, &mut buf, PROTO).await.unwrap(); // UID SEARCH
            server_end
                .write_all(b"* SEARCH 1001 1002 1010\r\nA0002 OK search done\r\n")
                .await
                .unwrap();
        });
        let t = Transport::from_stream(
            client_end,
            "imap.example.test",
            143,
            SocketSecurity::Plaintext,
            TlsSettings::default(),
        );
        let mut c = ImapClient::connect(t).await.unwrap();
        let uids = c.uid_search("ALL").await.unwrap();
        assert_eq!(uids, vec![1001, 1002, 1010]);
    }
}
