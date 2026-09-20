"""Mail-flow vertical e2e over the live compose stack (T-171).

Proves the whole sync-to-forensics vertical for real, against GreenMail
IMAP + the real kiwi-mail sync engine + the real forensics adapter:

  compose up mailpit+greenmail → IMAP APPEND seed → `sync_folder` →
  store rows → `event_from_live` → `RuleEngine` → deterministic findings.

The Rust leg lives in `kiwi-forensics/tests/vertical_mail_flow.rs` (it
needs both crates at once, so it cannot live in either crate's unit
suite). This module is the orchestrator in `infra/e2e/` house style
(stdlib unittest only): it starts the services it needs, waits for
them, documents the plaintext scope, and shells out to cargo.

Requires Docker + the compose stack. Skips — never fails — when the
daemon or the services are absent. Leaves services running afterwards
(dev-friendly; `docker compose down` remains the operator's call).

Usage (from repo root):
    python -m unittest discover -s infra/e2e -v
    # or:  python infra/e2e/test_mail_flow.py
"""
import imaplib
import os
import socket
import subprocess
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE = ROOT / ".env.example"
ENV_FILE = ROOT / ".env"


def run(cmd, timeout=120, env=None):
    return subprocess.run(
        cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout,
        env=env,
    )


def compose(*args, timeout=180):
    return run(
        ["docker", "compose", "--env-file", str(env_file()), *args],
        timeout=timeout,
    )


def env_file():
    return ENV_FILE if ENV_FILE.is_file() else ENV_EXAMPLE


def file_env():
    """Parse the compose env file into a dict (dev defaults live here)."""
    values = {}
    for line in env_file().read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


ENV = file_env()
IMAP_PORT = int(os.environ.get("GREENMAIL_IMAP_PORT") or ENV.get("GREENMAIL_IMAP_PORT", "1143"))
SMTP_PORT = int(os.environ.get("MAILPIT_SMTP_PORT") or ENV.get("MAILPIT_SMTP_PORT", "1025"))


def daemon_up():
    try:
        return run(["docker", "info"], timeout=30).returncode == 0
    except Exception:
        return False


def wait_for_imap_greeting(port, timeout=120):
    """True once GreenMail answers with an IMAP greeting."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                banner = sock.recv(128)
                if b"OK" in banner and b"IMAP" in banner:
                    return True
        except OSError:
            pass
        time.sleep(2)
    return False


def wait_for_smtp_banner(port, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                if sock.recv(128).startswith(b"220"):
                    return True
        except OSError:
            pass
        time.sleep(2)
    return False


class MailFlowVertical(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not daemon_up():
            raise unittest.SkipTest("docker daemon unavailable")
        up = compose("up", "-d", "mailpit", "greenmail", timeout=300)
        if up.returncode != 0:
            raise unittest.SkipTest("compose up failed: %s" % up.stderr[-500:])
        if not wait_for_imap_greeting(IMAP_PORT):
            raise unittest.SkipTest("greenmail IMAP never greeted")
        if not wait_for_smtp_banner(SMTP_PORT):
            raise unittest.SkipTest("mailpit SMTP never greeted")

    def test_capability_documents_plaintext_scope(self):
        """GreenMail offers no STARTTLS: plaintext verdicts are the honest
        expectation for this vertical, not a gap in the adapter."""
        mail = imaplib.IMAP4("127.0.0.1", IMAP_PORT)
        try:
            _, data = mail.capability()
        finally:
            try:
                mail.logout()
            except Exception:
                pass
        joined = b" ".join(data or [])
        self.assertNotIn(b"STARTTLS", joined.upper())

    def test_sync_store_adapter_finding_vertical(self):
        """The Rust leg: seed → sync_folder → store rows → adapter →
        KIWI-TRANSPORT-001 + KIWI-AUTH-001, byte-identical across runs."""
        env = dict(os.environ)
        env["KIWI_E2E"] = "1"
        env["GREENMAIL_IMAP_PORT"] = str(IMAP_PORT)
        proc = run(
            ["cargo", "test", "-p", "kiwi-forensics",
             "--test", "vertical_mail_flow"],
            timeout=600, env=env,
        )
        self.assertEqual(
            proc.returncode, 0,
            "vertical leg failed.\n--- stdout ---\n%s\n--- stderr ---\n%s"
            % (proc.stdout[-4000:], proc.stderr[-4000:]),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
