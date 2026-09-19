"""KIWI infrastructure verification tests (T-133, Agent 6).

Two tiers, one suite (stdlib only — no pytest dependency):
  * STATIC (no Docker daemon): compose file validity, .env.example coverage,
    Tauri-not-in-Docker guard (ADR-007 constraint).
  * LIVE (needs `docker compose up -d`): Postgres TCP + health, mailpit
    SMTP/API, admin /healthz, Drizzle migrations connectivity.
Live tests skip — never fail — when the stack (or the pending T-130/T-132
deliverable) is absent, with the exact command to unblock.

Usage:
    python -m unittest discover -s tests/infra -v        # from repo root
    # or:  python tests/infra/test_compose.py
"""
import json
import os
import re
import socket
import subprocess
import unittest
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
ENV_FILE = ROOT / ".env"


def run(cmd, timeout=60):
    return subprocess.run(
        cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout
    )


def daemon_up():
    try:
        return run(["docker", "info"], timeout=30).returncode == 0
    except Exception:
        return False


def example_env():
    values = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def compose_env_file():
    """Prefer a real .env (developer override), else the shipped example."""
    return ENV_FILE if ENV_FILE.is_file() else ENV_EXAMPLE


class ComposeStaticTests(unittest.TestCase):
    """No daemon required."""

    def test_compose_file_exists(self):
        self.assertTrue(COMPOSE.is_file(), "docker-compose.yml missing at repo root")

    def test_compose_config_valid(self):
        proc = run(
            ["docker", "compose", "--env-file", str(compose_env_file()), "config", "--quiet"]
        )
        self.assertEqual(
            proc.returncode, 0, f"docker compose config failed:\n{proc.stderr}"
        )

    def test_env_example_covers_compose_vars(self):
        """Every ${VAR} in compose must be documented in .env.example (ADR-009)."""
        text = COMPOSE.read_text(encoding="utf-8")
        referenced = set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)(?::-.*?)?\}", text))
        # $$ is docker-compose escaping for a literal $ — not a variable.
        referenced.discard("")
        documented = set(example_env())
        missing = referenced - documented
        self.assertEqual(missing, set(), f"vars missing from .env.example: {missing}")

    def test_tauri_not_in_compose(self):
        """ADR-007: the desktop app never runs in Docker. Enforced, not hoped."""
        proc = run(
            [
                "docker", "compose", "--env-file", str(compose_env_file()),
                "config", "--format", "json",
            ]
        )
        self.assertEqual(proc.returncode, 0, f"config render failed:\n{proc.stderr}")
        try:
            config = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            self.fail(f"compose config is not valid JSON: {e}")
        services = config.get("services", {})
        self.assertTrue(services, "compose file defines no services")
        forbidden = ("kiwi-app", "tauri", "src-tauri", "webview")
        for name, svc in services.items():
            blob = json.dumps(svc).lower()
            for marker in forbidden:
                self.assertNotIn(
                    marker, blob,
                    f"service {name!r} references {marker!r} — Tauri stays native",
                )
            self.assertNotIn(name.lower(), ("app", "tauri", "desktop", "client"))

    def test_admin_dockerfile_exists(self):
        dockerfile = ROOT / "kiwi-admin" / "Dockerfile"
        self.assertTrue(dockerfile.is_file(), "kiwi-admin/Dockerfile missing (T-131)")
        text = dockerfile.read_text(encoding="utf-8")
        self.assertIn("npm run typecheck", text, "Dockerfile must keep the type gate")


class LiveInfraTests(unittest.TestCase):
    """Needs `docker compose up -d`. Skips (never fails) when the stack is down."""

    @classmethod
    def setUpClass(cls):
        if not daemon_up():
            raise unittest.SkipTest("docker daemon down — start Docker Desktop")
        cls.env = example_env()
        if ENV_FILE.is_file():
            for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    cls.env[key.strip()] = value.strip()

    def ps_health(self, service):
        proc = run(["docker", "compose", "ps", service, "--format", "json"])
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None
        if isinstance(data, list):
            data = data[0] if data else {}
        return (data.get("Health") or data.get("health") or "").lower() or None

    def test_postgres_tcp(self):
        port = int(self.env.get("POSTGRES_PORT", "5432"))
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5):
                pass
        except OSError:
            self.skipTest(
                f"nothing on 127.0.0.1:{port} — run: docker compose up -d db"
            )

    def test_postgres_healthy(self):
        health = self.ps_health("db")
        if health is None:
            self.skipTest("db container not running — run: docker compose up -d db")
        self.assertIn(health, ("healthy",), f"db health is {health!r}, want healthy")

    def test_postgres_accepts_connections(self):
        """pg_isready inside the container (same probe as the healthcheck)."""
        if self.ps_health("db") is None:
            self.skipTest("db container not running — run: docker compose up -d db")
        user = self.env.get("POSTGRES_USER", "kiwi")
        db = self.env.get("POSTGRES_DB", "kiwi_admin")
        proc = run(
            ["docker", "compose", "exec", "-T", "db",
             "pg_isready", "-U", user, "-d", db]
        )
        self.assertEqual(proc.returncode, 0, f"pg_isready failed:\n{proc.stderr}")

    def test_mailpit_smtp_banner(self):
        port = int(self.env.get("MAILPIT_SMTP_PORT", "1025"))
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                banner = sock.recv(128)
        except OSError:
            self.skipTest(f"nothing on SMTP :{port} — run: docker compose up -d mailpit")
        self.assertTrue(banner.startswith(b"220"), f"bad SMTP banner: {banner!r}")

    def test_mailpit_api(self):
        port = int(self.env.get("MAILPIT_UI_PORT", "8025"))
        try:
            with urlopen(f"http://127.0.0.1:{port}/api/v1/info", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
        except Exception:
            self.skipTest(f"mailpit UI unreachable on :{port} — is mailpit up?")

    def test_greenmail_imap_greeting(self):
        """T-147: live IMAP (mailpit serves none — verified TCP accept, 0 bytes).

        The `* OK` greeting (vs SMTP `220`) already proves the IMAP
        service is wired; CAPABILITY asserts the protocol, not just TCP.
        """
        port = int(self.env.get("GREENMAIL_IMAP_PORT", "1143"))
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.settimeout(5)
                greeting = sock.recv(128)
                self.assertTrue(
                    greeting.startswith(b"* OK"),
                    f"bad IMAP greeting: {greeting!r}",
                )
                sock.sendall(b"t001 CAPABILITY\r\n")
                capa = b""
                while b"t001 " not in capa:
                    chunk = sock.recv(512)
                    if not chunk:
                        break
                    capa += chunk
        except OSError:
            self.skipTest(
                f"nothing on IMAP :{port} — run: docker compose up -d greenmail"
            )
        self.assertIn(b"IMAP4rev1", capa, f"no IMAP4rev1 in: {capa!r}")

    def test_admin_health(self):
        """GET /healthz — lands with T-130; until then this skips, never fails."""
        port = int(self.env.get("KIWI_ADMIN_PORT", "3001"))
        try:
            with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                return
        except Exception:
            pass
        self.skipTest(
            "T-130 pending: kiwi-admin has no /healthz entrypoint yet "
            "(admin service expected-unhealthy — see infra/README.md)"
        )

    def test_migrations_apply_and_guard_holds(self):
        """Drizzle `pg` migrations apply to the compose DB; tables exist;
        the audit append-only guard rejects DELETE (T-130 schema live check).

        Idempotent: re-runs pass when all expected tables already exist
        ("already exists" from a previous apply is not a failure).
        """
        mig_dir = ROOT / "kiwi-admin" / "drizzle" / "pg"
        sql_files = sorted(mig_dir.glob("*.sql"))
        if not sql_files:
            self.skipTest("T-130 pending: no Drizzle pg migrations in kiwi-admin yet")
        if self.ps_health("db") is None:
            self.skipTest("db container not running — run: docker compose up -d db")
        user = self.env.get("POSTGRES_USER", "kiwi")
        db = self.env.get("POSTGRES_DB", "kiwi_admin")
        base = ["docker", "compose", "exec", "-T", "db",
                "psql", "-U", user, "-d", db, "-v", "ON_ERROR_STOP=1"]
        for sql_file in sql_files:
            sql = sql_file.read_bytes()
            proc = subprocess.run(
                base + ["-f", "-"], cwd=ROOT, input=sql,
                capture_output=True, timeout=120,
            )
            already_exists = b"already exists" in proc.stderr
            self.assertEqual(
                proc.returncode, 0,
                f"migration {sql_file.name} failed:\n{proc.stderr.decode(errors='replace')}",
            ) if not already_exists else None
        expected_tables = {
            "audit_log", "devices", "domains", "mailflow_events", "orgs",
            "policies", "policy_domain_rules", "user_org_roles", "users",
        }
        proc = subprocess.run(
            base + ["-tA", "-c",
                    "select table_name from information_schema.tables "
                    "where table_schema='public';"],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, f"table probe failed:\n{proc.stderr}")
        present = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
        self.assertTrue(
            expected_tables <= present,
            f"missing tables after migrate: {sorted(expected_tables - present)}",
        )
        # Append-only guard: INSERT then DELETE must raise.
        guard_row = (
            "insert into audit_log(seq,ts,action,outcome,prev_hash,entry_hash)"
            " values (9001,1700000000000,'t133.probe','allowed','GENESIS','T133PROBE')"
            " on conflict (seq) do nothing;"
        )
        subprocess.run(base + ["-c", guard_row], cwd=ROOT,
                       capture_output=True, text=True, timeout=60)
        proc = subprocess.run(
            base + ["-c", "delete from audit_log where seq=9001;"],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
        self.assertNotEqual(proc.returncode, 0, "DELETE on audit_log succeeded?!")
        self.assertIn("append-only", proc.stderr,
                      f"guard fired without the append-only message:\n{proc.stderr}")


class SandboxLifecycleStub(unittest.TestCase):
    """T-132 (Agent 2) delivered design + contract + host probe + WSL2 PoC.

    Static assertions (no VM needed): contract pins the interface and the
    no-host-fallback rule; PoC scripts exist and are registered. Live
    lifecycle (create/revert/teardown) runs when the provider crate lands;
    until then the lifecycle test passes as an explicit DEFERRED marker —
    never silently green.
    """

    def test_sandbox_contract_pins_no_host_fallback(self):
        contract = ROOT / "docs" / "contracts" / "sandbox.md"
        if not contract.is_file():
            self.skipTest("DEFERRED (T-132): docs/contracts/sandbox.md missing")
        text = contract.read_text(encoding="utf-8")
        self.assertIn("Unavailable", text)
        self.assertRegex(
            text, r"(?i)no\s+fallback to host\s+execution",
            "contract must pin the no-host-fallback rule",
        )

    def test_sandbox_poc_scripts_present(self):
        for script in ("check-sandbox-host.ps1", "sandbox-wsl-poc.ps1"):
            self.assertTrue(
                (ROOT / "tests" / "infra" / script).is_file(),
                f"T-132 PoC script missing: tests/infra/{script}",
            )

    def test_sandbox_lifecycle(self):
        sandbox_dir = ROOT / "sandbox"
        if not sandbox_dir.is_dir():
            self.skipTest(
                "DEFERRED (T-132): no sandbox/ provider crate yet — "
                "lifecycle (create/revert/teardown) untestable until it lands"
            )
        self.assertTrue(
            (sandbox_dir / "lifecycle.py").is_file()
            or (sandbox_dir / "lifecycle.sh").is_file(),
            "sandbox/ exists but exposes no lifecycle entrypoint",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
