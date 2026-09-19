//! Prototype round-trip: send via kiwi-mail SMTP client → mailpit,
//! then fetch the same message back via kiwi-mail POP3 client.
//!
//! Prereq: docker compose up -d mailpit
//! Run:    cargo run -p kiwi-mail --example roundtrip_mailpit

use kiwi_mail::pop3::{Pop3Auth, Pop3Client, Pop3Config};
use kiwi_mail::smtp::{SendRequest, SmtpClient, SmtpConfig};
use kiwi_mail::transport::{SocketSecurity, TlsSettings, Transport};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ---- SEND (SMTP :1025, plaintext — local dev server) ----
    let t = Transport::connect("127.0.0.1", 1025, SocketSecurity::Plaintext, TlsSettings::default()).await?;
    let mut smtp = SmtpClient::connect(
        t,
        SmtpConfig { require_starttls: false, ..Default::default() },
    )
    .await?;
    let marker = format!("roundtrip-{}@kiwi.local", std::process::id());
    let msg = format!(
        "From: kiwi@kiwi.local\r\nTo: demo@mailpit.local\r\nSubject: KIWI round-trip\r\nMessage-ID: <{marker}>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nKIWI sent this with its own SMTP client and read it back with its own POP3 client.\r\n"
    );
    let out = smtp
        .send_mail(&SendRequest {
            from: "kiwi@kiwi.local".into(),
            to: vec!["demo@mailpit.local".into()],
            message: msg.into_bytes(),
        })
        .await?;
    println!("SMTP  → accepted={:?} rejected={:?}", out.accepted, out.rejected);

    // ---- RECEIVE (POP3 :1100) ----
    let t = Transport::connect("127.0.0.1", 1100, SocketSecurity::Plaintext, TlsSettings::default()).await?;
    let mut pop3 = Pop3Client::connect(
        t,
        Pop3Config { require_stls: false, allow_plaintext_auth: true },
    )
    .await?;
    pop3.authenticate(&Pop3Auth::UserPass {
        user: "demo".into(),
        password: Zeroizing::new("demo".into()),
    })
    .await?;
    let (count, bytes) = pop3.stat().await?;
    println!("POP3  → stat: {count} messages, {bytes} bytes");
    let list = pop3.retr(count as u32).await?;
    let body = String::from_utf8_lossy(&list);
    let hit = body.contains(&marker);
    println!("POP3  → retr #{count}: {} bytes, our message found: {hit}", list.len());
    println!("----\n{body}\n----");
    pop3.quit().await?;
    if !hit {
        return Err("round-trip failed: message not found".into());
    }
    println!("ROUND TRIP OK — KIWI sent and received real mail.");
    Ok(())
}
