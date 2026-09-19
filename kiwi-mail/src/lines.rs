//! Bounded line/block IO shared by the SMTP/IMAP/POP3 clients.
//!
//! All remote input is untrusted (SECURITY.md rule 9): every read is
//! bounded, CRLF-terminated, and protocol-agnostic.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{MailError, Result};

/// Hard caps on remote input — no unbounded buffering of peer data.
pub const MAX_LINE: usize = 16 * 1024;
pub const MAX_BLOCK: usize = 64 * 1024 * 1024;

/// Read a single CRLF/LF-terminated line (terminator stripped).
/// `protocol` is used in error messages. Errors on over-long lines.
pub async fn read_line<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    protocol: &'static str,
) -> Result<Vec<u8>> {
    loop {
        let byte = stream.read_u8().await?;
        buf.push(byte);
        if byte == b'\n' {
            break;
        }
        if buf.len() > MAX_LINE {
            return Err(MailError::Protocol {
                protocol,
                detail: format!("over-long line (>{MAX_LINE} bytes)"),
            });
        }
    }
    let mut line = std::mem::take(buf);
    while matches!(line.last(), Some(b'\r' | b'\n')) {
        line.pop();
    }
    Ok(line)
}

/// Write bytes + CRLF.
pub async fn write_line<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<()> {
    stream.write_all(bytes).await?;
    stream.write_all(b"\r\n").await?;
    Ok(())
}

/// Read a dot-terminated multiline block (SMTP DATA / POP3 RETR style):
/// lines until a lone `.`; leading dots un-stuffed per RFC 5321 §4.5.2.
/// `limit` bounds the returned payload.
pub async fn read_dot_block<S: AsyncRead + Unpin>(
    stream: &mut S,
    protocol: &'static str,
    limit: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut scratch = Vec::new();
    loop {
        let line = read_line(stream, &mut scratch, protocol).await?;
        if line == b"." {
            return Ok(out);
        }
        let content = if line.starts_with(b"..") {
            &line[1..]
        } else {
            &line[..]
        };
        out.extend_from_slice(content);
        out.extend_from_slice(b"\r\n");
        if out.len() > limit {
            return Err(MailError::Protocol {
                protocol,
                detail: format!("dot block exceeded {limit} bytes"),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn line_reads_and_trims_crlf() {
        let (mut a, mut b) = duplex(64);
        tokio::spawn(async move {
            b.write_all(b"+OK hello\r\n-ERR bye\n").await.unwrap();
        });
        let mut buf = Vec::new();
        assert_eq!(
            read_line(&mut a, &mut buf, "test").await.unwrap(),
            b"+OK hello"
        );
        assert_eq!(
            read_line(&mut a, &mut buf, "test").await.unwrap(),
            b"-ERR bye"
        );
    }

    #[tokio::test]
    async fn dot_block_unstuffs() {
        let (mut a, mut b) = duplex(4096);
        tokio::spawn(async move {
            b.write_all(b"line1\r\n..dotline\r\n.\r\n").await.unwrap();
        });
        let out = read_dot_block(&mut a, "test", 1024).await.unwrap();
        assert_eq!(out, b"line1\r\n.dotline\r\n");
    }
}
