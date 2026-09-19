//! Prototype demo: send a real email through kiwi-mail's own SMTP client
//! to the local mailpit dev server (docker compose up -d mailpit).
//!
//! Run: cargo run -p kiwi-mail --example send_mailpit
//! Then open http://localhost:8025 to see the message.

use kiwi_mail::smtp::{SendRequest, SmtpClient, SmtpConfig};
use kiwi_mail::transport::{SocketSecurity, TlsSettings, Transport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport =
        Transport::connect("127.0.0.1", 1025, SocketSecurity::Plaintext, TlsSettings::default())
            .await?;
    println!("connected: {}:{} ({:?})", transport.host(), transport.port(), transport.socket_security());

    let mut client = SmtpClient::connect(
        transport,
        SmtpConfig {
            require_starttls: false,
            ..Default::default()
        },
    )
    .await?;

    let msg = b"From: kiwi@kiwi.local\r\nTo: demo@mailpit.local\r\nSubject: KIWI prototype hello\r\nMessage-ID: <proto-1@kiwi.local>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSent by kiwi-mail's own SMTP client. This is the first real end-to-end send.\r\n";
    let outcome = client
        .send_mail(&SendRequest {
            from: "kiwi@kiwi.local".into(),
            to: vec!["demo@mailpit.local".into()],
            message: msg.to_vec(),
        })
        .await?;

    println!("accepted: {:?}", outcome.accepted);
    println!("rejected: {:?}", outcome.rejected);
    println!("data reply: {:?}", outcome.data_reply.map(|r| r.message()));
    Ok(())
}
