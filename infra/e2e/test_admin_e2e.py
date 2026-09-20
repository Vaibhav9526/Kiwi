"""kiwi-admin end-to-end tests over the live compose stack (T-149).

Drives the real service the way a caller does — HTTP in, database out — and
proves the two properties the audit log actually claims:

  1. TAMPER REJECTION. The DB-level append-only guard refuses UPDATE and DELETE
     on `audit_log` from any connection (drizzle/{pg,sqlite}/0001_*).
  2. TAMPER DETECTION. The guard has an honest limit — a file/superuser holder
     can DROP the trigger — so hash-chain verification on read is the detection
     layer behind it. This suite bypasses the guard deliberately and asserts
     that `GET /api/v1/audit/verify` then reports the break.

Two dialect legs run the same flow. Which one is live is read from the
service's own startup log (`server.ts` prints the dialect it opened), so
whichever driver the container selected is the one exercised, and the other
skips with the reason. Compose sets DATABASE_URL, so the containerized service
is normally the Postgres leg.

Requires Docker. Skips — never fails — when the daemon or the stack is absent.

Usage (from repo root):
    python -m unittest discover -s infra/e2e -v
    # or:  python infra/e2e/test_admin_e2e.py
"""
import json
import os
import re
import subprocess
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
ENV_FILE = ROOT / ".env"

# The service writes its SQLite file relative to its WORKDIR (Dockerfile /app).
CONTAINER_DB = "/app/kiwi-admin.db"
HEALTH_TIMEOUT = 180


def run(cmd, timeout=120):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def compose(*args, timeout=120):
    return run(
        ["docker", "compose", "--env-file", str(env_file()), *args], timeout=timeout
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
ADMIN_PORT = int(os.environ.get("KIWI_ADMIN_PORT") or ENV.get("KIWI_ADMIN_PORT", "3001"))
BASE = f"http://127.0.0.1:{ADMIN_PORT}"

# Every call carries a role: the service's header actors are FAIL-CLOSED, so a
# request without `x-kiwi-roles` is refused rather than defaulted to admin.
ORG_ADMIN = {"x-kiwi-subject": "e2e-admin", "x-kiwi-roles": "org_admin"}
VIEWER = {"x-kiwi-subject": "e2e-viewer", "x-kiwi-roles": "viewer"}


def daemon_up():
    try:
        return run(["docker", "info"], timeout=30).returncode == 0
    except Exception:
        return False


def http(method, path, body=None, headers=None, timeout=20):
    """Return (status, parsed_json_or_None). Transport errors surface as status 0."""
    url = BASE + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = Request(url, data=data, method=method)
    req.add_header("content-type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, (json.loads(raw) if raw else None)
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, (json.loads(raw) if raw else None)
        except json.JSONDecodeError:
            return exc.code, None
    except (URLError, OSError):
        return 0, None


def wait_for_health(timeout=HEALTH_TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, body = http("GET", "/healthz")
        if status == 200 and isinstance(body, dict) and body.get("status") == "ok":
            return True
        time.sleep(3)
    return False


def service_dialect():
    """Which driver the running service opened: "sqlite", "postgres", or None.

    Read from the service's own startup line rather than inferred from data:
    a freshly migrated Postgres holds zero audit rows, so a probe that required
    rows would skip the very leg it was meant to enable.
    """
    proc = compose("logs", "--no-log-prefix", "admin", timeout=60)
    match = re.search(r"listening on [^\n]*\((sqlite|postgres)", proc.stdout + proc.stderr)
    return match.group(1) if match else None


def sqlite_exec(js, timeout=60):
    """Run a Node one-liner inside the admin container (better-sqlite3 is installed there)."""
    return compose("exec", "-T", "admin", "node", "-e", js, timeout=timeout)


def sqlite_script(body):
    """Wrap a script body with a better-sqlite3 handle on the service database."""
    return (
        f"const D=require('better-sqlite3');"
        f"const db=new D(process.env.KIWI_ADMIN_DB||'{CONTAINER_DB}');"
        f"try{{{body}}}catch(e){{console.log('ERROR:'+e.message);}}"
    )


def pg_query(sql, timeout=60):
    """Run SQL against the compose Postgres; returns (returncode, stdout, stderr)."""
    user = ENV.get("POSTGRES_USER", "kiwi")
    name = ENV.get("POSTGRES_DB", "kiwi_admin")
    proc = compose(
        "exec", "-T", "db", "psql", "-U", user, "-d", name, "-tAc", sql, timeout=timeout
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def pg_exec_script(sql):
    """Run SQL allowing failure, returning (returncode, stdout+stderr)."""
    user = ENV.get("POSTGRES_USER", "kiwi")
    name = ENV.get("POSTGRES_DB", "kiwi_admin")
    proc = compose(
        "exec", "-T", "db",
        "psql", "-U", user, "-d", name, "-v", "ON_ERROR_STOP=1", "-tAc", sql,
        timeout=60,
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def stack_up():
    """Start the services this suite needs. Returns True when the API answers."""
    if not daemon_up():
        return False
    # `db` is a declared dependency of `admin`; naming both keeps `up` explicit
    # per the T-149 instructions.
    compose("up", "-d", "db", "admin", timeout=420)
    return wait_for_health()


class Backend:
    """Dialect-specific introspection: how to read and tamper with `audit_log`."""

    name = "base"
    append_only_error = ""

    def audit_row(self, seq):
        raise NotImplementedError

    def try_update(self, seq, value):
        """Attempt a direct UPDATE. Returns the raised message, or None if it landed."""
        raise NotImplementedError

    def try_delete(self, seq):
        raise NotImplementedError

    def drop_update_guard(self):
        raise NotImplementedError

    def restore_update_guard(self):
        raise NotImplementedError

    def count_audit_rows(self):
        raise NotImplementedError


class SqliteBackend(Backend):
    name = "sqlite"
    append_only_error = "audit_log is append-only: UPDATE rejected"
    # Mirrors drizzle/sqlite/0001_audit-append-only-guard.sql (UPDATE trigger).
    guard_sql = (
        "CREATE TRIGGER `audit_log_no_update` BEFORE UPDATE ON `audit_log` "
        "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE rejected'); END;"
    )

    def audit_row(self, seq):
        js = sqlite_script(
            f"const r=db.prepare('SELECT seq,action,entry_hash FROM audit_log WHERE seq=?')"
            f".get({int(seq)});console.log(r?JSON.stringify(r):'null');"
        )
        proc = sqlite_exec(js)
        out = proc.stdout.strip().splitlines()
        if not out or out[-1] == "null":
            return None
        return json.loads(out[-1])

    def try_update(self, seq, value):
        js = sqlite_script(
            f"db.prepare('UPDATE audit_log SET action=? WHERE seq=?')"
            f".run('{value}',{int(seq)});console.log('LANDED');"
        )
        return _raised(sqlite_exec(js), "LANDED")

    def try_delete(self, seq):
        js = sqlite_script(
            f"db.prepare('DELETE FROM audit_log WHERE seq=?').run({int(seq)});"
            f"console.log('LANDED');"
        )
        return _raised(sqlite_exec(js), "LANDED")

    def drop_update_guard(self):
        sqlite_exec(sqlite_script("db.exec('DROP TRIGGER IF EXISTS `audit_log_no_update`');"))

    def restore_update_guard(self):
        sqlite_exec(sqlite_script(f"db.exec({json.dumps(self.guard_sql)});"))

    def count_audit_rows(self):
        js = sqlite_script("console.log(String(db.prepare('SELECT COUNT(*) c FROM audit_log').get().c));")
        out = sqlite_exec(js).stdout.strip().splitlines()
        return int(out[-1]) if out else 0


class PostgresBackend(Backend):
    name = "postgres"
    append_only_error = "append-only"
    # Mirrors drizzle/pg/0001_audit-append-only-guard.sql (UPDATE trigger).
    guard_sql = (
        "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON \"audit_log\" "
        "FOR EACH ROW EXECUTE FUNCTION audit_log_reject_write();"
    )

    def audit_row(self, seq):
        code, out, _ = pg_query(f"SELECT seq||'|'||action FROM audit_log WHERE seq={int(seq)}")
        if code != 0 or not out:
            return None
        seq_text, _, action = out.partition("|")
        return {"seq": int(seq_text), "action": action}

    def try_update(self, seq, value):
        code, out = pg_exec_script(f"UPDATE audit_log SET action='{value}' WHERE seq={int(seq)};")
        return None if code == 0 else out

    def try_delete(self, seq):
        code, out = pg_exec_script(f"DELETE FROM audit_log WHERE seq={int(seq)};")
        return None if code == 0 else out

    def drop_update_guard(self):
        pg_exec_script("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;")

    def restore_update_guard(self):
        pg_exec_script(self.guard_sql)

    def count_audit_rows(self):
        code, out, _ = pg_query("SELECT COUNT(*) FROM audit_log")
        return int(out) if code == 0 and out.isdigit() else 0


def _raised(proc, success_marker):
    """Interpret a sqlite_exec result: None when the statement landed, else the message."""
    text = (proc.stdout + proc.stderr).strip()
    for line in text.splitlines():
        if line.startswith("LANDED") or line == success_marker:
            return None
        if line.startswith("ERROR:"):
            return line[len("ERROR:"):].strip()
    return text or f"no output (exit {proc.returncode})"


class AdminE2E(unittest.TestCase):
    """Stack lifecycle + the shared flow. Declares no tests of its own."""

    @classmethod
    def setUpClass(cls):
        if not stack_up():
            raise unittest.SkipTest(
                "compose stack unavailable — run: "
                "docker compose up -d db admin (daemon off or admin unhealthy)"
            )

    # -- helpers ------------------------------------------------------------

    def create_org(self, name):
        status, body = http("POST", "/api/v1/orgs", {"name": name}, ORG_ADMIN)
        self.assertEqual(status, 201, f"create org failed: {status} {body}")
        return body["id"]

    def fetch_audit(self, query="?limit=1000"):
        """Audit reads need `audit.read`, so they carry a role like every call."""
        status, body = http("GET", f"/api/v1/audit{query}", None, ORG_ADMIN)
        self.assertEqual(status, 200, f"audit read failed: {status} {body}")
        return body

    def exercise_full_flow(self):
        """orgs -> users -> roles -> policies -> evaluate -> mailflow. Returns the org id."""
        stamp = str(int(time.time() * 1000))
        org = self.create_org(f"E2E Org {stamp}")

        status, user = http(
            "POST", f"/api/v1/orgs/{org}/users", {"email": f"user{stamp}@kiwi-test.invalid"}, ORG_ADMIN
        )
        self.assertEqual(status, 201, f"create user failed: {status} {user}")

        status, listed = http("GET", f"/api/v1/orgs/{org}/users", None, ORG_ADMIN)
        self.assertEqual(status, 200)
        self.assertTrue(
            any(u["email"] == f"user{stamp}@kiwi-test.invalid" for u in listed["items"]),
            "created user must be listed",
        )

        status, _ = http(
            "PUT", f"/api/v1/orgs/{org}/users/{user['id']}/role", {"role": "viewer"}, ORG_ADMIN
        )
        self.assertEqual(status, 200, "grant role failed")

        # TLS labels must be keys of TLS_VERSION_ALIASES (types.ts) — `tls1.2`,
        # not `1.2`. A bare `1.2` is not an alias and both the policy parser and
        # the mailflow parser reject it with 400.
        status, policy = http(
            "POST",
            f"/api/v1/orgs/{org}/policies",
            {
                "name": "e2e policy",
                "enabled": True,
                "min_tls": "tls1.2",
                "external_recipients": "warn",
                "domain_rules": [{"domain": "blocked.invalid", "action": "block"}],
            },
            ORG_ADMIN,
        )
        self.assertEqual(status, 201, f"create policy failed: {status} {policy}")

        status, verdict = http(
            "POST",
            f"/api/v1/orgs/{org}/policies/evaluate-outbound",
            {"sender": "a@kiwi-test.invalid", "recipients": ["b@blocked.invalid"], "tls_version": "tls1.2"},
            ORG_ADMIN,
        )
        self.assertEqual(status, 200, f"evaluate failed: {status} {verdict}")

        status, ingested = http(
            "POST",
            "/api/v1/mailflow/events",
            {
                "direction": "outbound",
                "sender": "a@kiwi-test.invalid",
                "recipient": "b@blocked.invalid",
                "ts": int(time.time()),
                "message_id": f"<e2e-{stamp}@kiwi-test.invalid>",
                "tls_version": "tls1.2",
                "security_status": "clean",
                "policy_verdict": "block",
                "org_id": org,
            },
            ORG_ADMIN,
        )
        self.assertEqual(status, 201, f"mailflow ingest failed: {status} {ingested}")

        status, events = http("GET", f"/api/v1/mailflow/events?org={org}&limit=10", None, ORG_ADMIN)
        self.assertEqual(status, 200)
        self.assertTrue(events["items"], "ingested mailflow event must be queryable")
        return org

    def assert_chain_valid(self, msg="audit chain must verify"):
        status, body = http("GET", "/api/v1/audit/verify?limit=10000", None, ORG_ADMIN)
        self.assertEqual(status, 200, f"verify failed: {status} {body}")
        self.assertTrue(
            body["valid"],
            f"{msg}: {body.get('error')}. If a previous run was killed between dropping the "
            "append-only guard and restoring it, this is a genuinely broken chain, not a "
            "flake — the probe rewrites seq 1 in place. Postgres keeps its rows in the "
            "`pgdata` volume, so reset it with `docker compose down -v` and re-run.",
        )
        self.assertIsNone(body["error"])
        self.assertGreater(body["checked"], 0, "verify must actually check rows")


class TransportLeg(AdminE2E):
    """Dialect-independent guarantees. Always runs against the live stack."""

    def test_service_listens_on_the_published_port(self):
        """Regression guard for the compose env bug: the service reads
        KIWI_ADMIN_PORT, not PORT. If compose sets the wrong name the container
        listens on the 8471 default and this fails."""
        status, body = http("GET", "/healthz")
        self.assertEqual(status, 200, f"admin unreachable on published port {ADMIN_PORT}")
        self.assertEqual(body["service"], "kiwi-admin")

    def test_healthz_reports_contract_version(self):
        status, body = http("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertIn("contract", body)

    def test_the_service_reports_which_dialect_it_opened(self):
        self.assertIn(service_dialect(), ("sqlite", "postgres"), "service must log its dialect")

    def test_audit_routes_require_a_role(self):
        """Regression guard (defect 3): the audit routes enforce `audit.read`,
        and a missing or unparseable role header fails closed rather than
        defaulting to org_admin."""
        for path in ("/api/v1/audit?limit=5", "/api/v1/audit/verify?limit=10"):
            status, _ = http("GET", path, None, {"x-kiwi-subject": "e2e-anonymous"})
            self.assertEqual(status, 403, f"{path} must refuse a role-less caller")

            status, _ = http(
                "GET", path, None, {"x-kiwi-subject": "typo", "x-kiwi-roles": "org-admin,admin,superuser"}
            )
            self.assertEqual(status, 403, f"{path} must not accept an unrecognized role name")

        # A viewer holds audit.read, so the read is allowed.
        status, _ = http("GET", "/api/v1/audit?limit=5", None, VIEWER)
        self.assertEqual(status, 200)


class DialectLeg(AdminE2E):
    """Abstract: the flow + tamper tests, run by each dialect subclass.

    Declares tests but no backend, so it must not be collected itself —
    otherwise unittest runs it and every test dies on `self.backend`.
    """

    backend: Backend

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls is DialectLeg:
            raise unittest.SkipTest("abstract base — see SqliteLeg and PostgresLeg")

    def test_full_admin_flow_over_http(self):
        """orgs, users, roles, policies, evaluate-outbound and mailflow all work end to end."""
        self.exercise_full_flow()

    def test_rbac_denial_is_refused_and_audited(self):
        """A viewer cannot mutate, and the refusal is itself recorded."""
        org = self.create_org(f"E2E RBAC {int(time.time() * 1000)}")
        status, body = http(
            "POST", f"/api/v1/orgs/{org}/policies",
            {"name": "denied", "enabled": True, "external_recipients": "allow", "domain_rules": []},
            VIEWER,
        )
        self.assertEqual(status, 403, f"viewer must not create policies: {status} {body}")

        denied = [row for row in self.fetch_audit()["items"] if row["outcome"] == "denied"]
        self.assertTrue(denied, "a denied authorization must leave an audit entry")

    def test_audit_org_filter_actually_narrows(self):
        """Regression guard (defect 4): `?org=` was accepted and ignored."""
        org = self.exercise_full_flow()
        scoped = self.fetch_audit(f"?org={org}&limit=1000")["items"]
        everything = self.fetch_audit()["items"]

        self.assertTrue(scoped, "the org's own audit rows must come back")
        self.assertLess(len(scoped), len(everything), "?org= must narrow the result")
        # `org.create` is audited with a NULL org_id (a platform-level act), so
        # it belongs to no org and must not appear in an org-scoped read.
        self.assertFalse(any(r["action"] == "org.create" for r in scoped))
        self.assertTrue(any(r["action"] == "policy.create" for r in scoped))

    def test_append_only_guard_rejects_update_and_delete(self):
        """Guard layer: raw SQL cannot rewrite or remove audit history."""
        self.exercise_full_flow()
        self.assertGreater(self.backend.count_audit_rows(), 0, "no audit rows to tamper with")

        update_msg = self.backend.try_update(1, "tampered-by-e2e")
        self.assertIsNotNone(update_msg, "UPDATE was NOT rejected — append-only guard is missing")
        self.assertIn(self.backend.append_only_error.split(":")[0], update_msg)

        delete_msg = self.backend.try_delete(1)
        self.assertIsNotNone(delete_msg, "DELETE was NOT rejected — append-only guard is missing")

        self.assert_chain_valid("history survived the tamper attempts")

    def test_chain_detects_tampering_when_the_guard_is_bypassed(self):
        """Detection layer: with the trigger dropped, verify() still catches the edit."""
        self.exercise_full_flow()
        original = self.backend.audit_row(1)
        self.assertIsNotNone(original, "seq 1 missing — cannot run the tamper probe")

        self.backend.drop_update_guard()
        try:
            landed = self.backend.try_update(1, "tampered-by-e2e")
            self.assertIsNone(landed, f"with the guard dropped the UPDATE should land: {landed}")

            status, body = http("GET", "/api/v1/audit/verify?limit=10000", None, ORG_ADMIN)
            self.assertEqual(status, 200)
            self.assertFalse(body["valid"], "verify() must detect a rewritten row")
            self.assertIn("chain broken at seq 1", body["error"] or "")
        finally:
            # Put the row and the guard back, so the suite leaves the chain
            # consistent and re-runnable.
            self.backend.try_update(1, original["action"])
            self.backend.restore_update_guard()

        self.assert_chain_valid("chain must verify again once the row is restored")

    def test_audit_is_ordered_and_contiguous(self):
        """seq is contiguous from 1 — the property verify() relies on for gap detection."""
        self.exercise_full_flow()
        seqs = [row["seq"] for row in self.fetch_audit()["items"]]
        self.assertTrue(seqs, "audit log is empty after activity")
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)), "audit seq must be contiguous from 1")


class SqliteLeg(DialectLeg):
    """The local-first dialect. Runs only when the service opened SQLite."""

    backend = SqliteBackend()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        dialect = service_dialect()
        if dialect != "sqlite":
            raise unittest.SkipTest(
                f"service opened '{dialect}', not sqlite — compose passes DATABASE_URL, so "
                "the containerized service takes the Postgres path. The SQLite guard is "
                "covered in-process by kiwi-admin/tests/audit.guard.test.ts."
            )

    def test_migrations_applied_expected_tables_exist(self):
        """Startup migration ran: the tables the API depends on are present."""
        js = sqlite_script(
            "const rows=db.prepare(\"SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '__drizzle%'\").all();"
            "console.log(JSON.stringify(rows.map(r=>r.name)));"
        )
        out = sqlite_exec(js).stdout.strip().splitlines()
        self.assertTrue(out, "no sqlite_master output")
        tables = set(json.loads(out[-1]))
        for expected in ["audit_log", "orgs", "users", "policies"]:
            self.assertIn(expected, tables, f"table {expected} missing — migrations did not run")


class PostgresLeg(DialectLeg):
    """The primary dialect (ADR-006). Runs when the service opened Postgres."""

    backend = PostgresBackend()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        dialect = service_dialect()
        if dialect != "postgres":
            raise unittest.SkipTest(
                f"service opened '{dialect}', not postgres — DATABASE_URL is unset or the "
                "container failed to reach the db service. Wiring lives in "
                "kiwi-admin/src/services.ts::createServiceContainer."
            )

    def test_migrations_applied_expected_tables_exist(self):
        """The Drizzle pg migrations ran against the compose database."""
        code, out, err = pg_query(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
        )
        self.assertEqual(code, 0, f"psql failed: {err}")
        tables = set(out.splitlines())
        for expected in ["audit_log", "orgs", "users", "policies"]:
            self.assertIn(expected, tables, f"table {expected} missing — pg migrations did not run")


if __name__ == "__main__":
    unittest.main(verbosity=2)
