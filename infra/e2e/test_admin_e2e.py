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
import hashlib
import hmac
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
SECURITY_ADMIN = {"x-kiwi-subject": "e2e-security", "x-kiwi-roles": "security_admin"}
VIEWER = {"x-kiwi-subject": "e2e-viewer", "x-kiwi-roles": "viewer"}
# T-259/§13: the only identity the GLOBAL whole-chain export accepts.
# org_admin keeps `audit.export` org-scoped (the /orgs/{id}/audit/export route).
SYSTEM_ADMIN = {"x-kiwi-subject": "e2e-sysadmin", "x-kiwi-roles": "system-admin"}


def export_key():
    """The signing key the *service* is using for the audit export (T-179).

    Compose interpolates `${KIWI_AUDIT_EXPORT_KEY}` with shell environment
    taking precedence over the env file, so mirror that order here rather than
    reading only the file — otherwise a caller who exports the variable inline
    would see the test recompute against the wrong key.
    """
    return (os.environ.get("KIWI_AUDIT_EXPORT_KEY") or ENV.get("KIWI_AUDIT_EXPORT_KEY") or "").strip()


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


def http_text(method, path, headers=None, timeout=30):
    """Return (status, content_type, raw_body) — for responses that are not JSON.

    The audit export (T-179) is NDJSON, so `http()` would fail to parse it and
    the line structure is the thing under test anyway.
    """
    req = Request(BASE + path, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("content-type", ""), resp.read().decode("utf-8")
    except HTTPError as exc:
        ctype = exc.headers.get("content-type", "") if exc.headers else ""
        return exc.code, ctype, exc.read().decode("utf-8", "replace")
    except (URLError, OSError):
        return 0, "", ""


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

    # -- device rows (T-193/H3: revocation is org-scoped) -------------------
    # No HTTP route creates devices, so the H3 probe inserts the row the way
    # the service would and exercises the real revoke path against it.

    def create_device(self, org_id, label):
        raise NotImplementedError

    def device_revoked(self, device_id):
        raise NotImplementedError

    def delete_device(self, device_id):
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

    def create_device(self, org_id, label):
        import uuid

        dev = f"dev-e2e-{uuid.uuid4().hex[:12]}"
        js = sqlite_script(
            "db.prepare('INSERT INTO devices (id, org_id, label, revoked, created_at) VALUES (?,?,?,?,?)')"
            f".run({json.dumps(dev)},{json.dumps(org_id)},{json.dumps(label)},0,{int(time.time() * 1000)});"
            "console.log('OK');"
        )
        proc = sqlite_exec(js)
        if "OK" not in proc.stdout:
            raise AssertionError(f"device insert failed: {proc.stdout} {proc.stderr}")
        return dev

    def device_revoked(self, device_id):
        js = sqlite_script(
            f"const r=db.prepare('SELECT revoked FROM devices WHERE id=?').get({json.dumps(device_id)});"
            "console.log(r?String(r.revoked):'missing');"
        )
        out = sqlite_exec(js).stdout.strip().splitlines()
        return out and out[-1] == "1"

    def delete_device(self, device_id):
        sqlite_exec(sqlite_script(f"db.prepare('DELETE FROM devices WHERE id=?').run({json.dumps(device_id)});"))


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

    def create_device(self, org_id, label):
        import uuid

        dev = f"dev-e2e-{uuid.uuid4().hex[:12]}"
        now_ms = int(time.time() * 1000)
        code, out = pg_exec_script(
            "INSERT INTO devices (id, org_id, label, revoked, created_at) VALUES "
            f"('{dev}','{org_id}','{label}',false,{now_ms});"
        )
        if code != 0:
            raise AssertionError(f"device insert failed: {out}")
        return dev

    def device_revoked(self, device_id):
        code, out, _ = pg_query(f"SELECT revoked FROM devices WHERE id='{device_id}'")
        return code == 0 and out.strip().lower() in ("t", "true", "1")

    def delete_device(self, device_id):
        pg_exec_script(f"DELETE FROM devices WHERE id='{device_id}';")


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
        # Org-scoped calls bind the org (T-193/H2): a null-org actor holds no
        # org scope, so the platform bootstrap headers stop working here.
        bound = {"x-kiwi-subject": "e2e-admin", "x-kiwi-roles": "org_admin", "x-kiwi-org": org}

        status, user = http(
            "POST", f"/api/v1/orgs/{org}/users", {"email": f"user{stamp}@kiwi-test.invalid"}, bound
        )
        self.assertEqual(status, 201, f"create user failed: {status} {user}")

        status, listed = http("GET", f"/api/v1/orgs/{org}/users", None, bound)
        self.assertEqual(status, 200)
        self.assertTrue(
            any(u["email"] == f"user{stamp}@kiwi-test.invalid" for u in listed["items"]),
            "created user must be listed",
        )

        status, _ = http(
            "PUT", f"/api/v1/orgs/{org}/users/{user['id']}/role", {"role": "viewer"}, bound
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
            bound,
        )
        self.assertEqual(status, 201, f"create policy failed: {status} {policy}")

        status, verdict = http(
            "POST",
            f"/api/v1/orgs/{org}/policies/evaluate-outbound",
            {"sender": "a@kiwi-test.invalid", "recipients": ["b@blocked.invalid"], "tls_version": "tls1.2"},
            bound,
        )
        self.assertEqual(status, 200, f"evaluate failed: {status} {verdict}")

        status, ingested = http(
            "POST",
            "/api/v1/mailflow/events",
            {
                "direction": "outbound",
                "sender": "a@kiwi-test.invalid",
                "recipient": "b@blocked.invalid",
                # Caller-supplied message time, Unix milliseconds per contract §4.
                "ts": int(time.time() * 1000),
                "message_id": f"<e2e-{stamp}@kiwi-test.invalid>",
                "tls_version": "tls1.2",
                "security_status": "clean",
                "policy_verdict": "block",
                "org_id": org,
            },
            bound,
        )
        self.assertEqual(status, 201, f"mailflow ingest failed: {status} {ingested}")

        status, events = http("GET", f"/api/v1/mailflow/events?org={org}&limit=10", None, bound)
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

    def test_audit_export_is_ndjson_of_the_whole_chain(self):
        """T-179: the export is NDJSON, covers every row, and carries the
        chain-state verdict for exactly those rows."""
        self.exercise_full_flow()
        status, ctype, text = http_text("GET", "/api/v1/audit/export", SYSTEM_ADMIN)
        self.assertEqual(status, 200, f"export failed: {status} {text[:200]}")
        # NDJSON: a JSON response would have escaped the newlines and destroyed
        # the line structure the format is defined by.
        self.assertIn("application/x-ndjson", ctype)

        lines = [line for line in text.split("\n") if line]
        self.assertGreaterEqual(len(lines), 3, "header + chain_state + signature at minimum")
        self.assertFalse(text.endswith("\n\n"), "no trailing blank line")

        header = json.loads(lines[0])
        self.assertEqual(header["type"], "header")
        self.assertEqual(header["version"], "kiwi.audit-export/1")
        self.assertEqual(header["first_seq"], 1, "the export always starts at genesis")
        self.assertEqual(header["rows"], len(lines) - 3)
        self.assertGreater(header["rows"], 0, "activity above must have produced audit rows")
        # The header's window must describe the rows actually shipped.
        self.assertEqual(json.loads(lines[1])["seq"], header["first_seq"])
        self.assertEqual(json.loads(lines[header["rows"]])["seq"], header["last_seq"])

        state = json.loads(lines[-2])
        self.assertEqual(state["type"], "chain_state")
        self.assertTrue(state["valid"], f"live chain must verify: {state.get('error')}")
        self.assertIsNone(state["error"])
        self.assertEqual(state["checked"], header["rows"], "every exported row must have been verified")
        self.assertEqual(state["last_seq"], header["last_seq"])
        self.assertEqual(state["head_hash"], json.loads(lines[header["rows"]])["entry_hash"])

        signature = json.loads(lines[-1])
        self.assertEqual(signature["type"], "signature")
        self.assertEqual(signature["covers_through"], len(lines) - 1)

    def test_audit_export_signature_is_recomputable(self):
        """T-179: an outside verifier holding only the key and the artifact can
        check it — that is the whole point of exporting instead of printing."""
        key = export_key()
        if not key:
            self.skipTest(
                "KIWI_AUDIT_EXPORT_KEY is unset in .env and .env.example, so the service "
                "exports unsigned (honest, but there is nothing to recompute). Add it to "
                ".env — an existing .env predating T-179 will not have it."
            )
        self.exercise_full_flow()
        status, _, text = http_text("GET", "/api/v1/audit/export", SYSTEM_ADMIN)
        self.assertEqual(status, 200)
        lines = [line for line in text.split("\n") if line]
        signature = json.loads(lines[-1])

        self.assertTrue(signature["signed"], "compose supplies the key, so the live export must be signed")
        self.assertEqual(signature["alg"], "hmac-sha256")
        self.assertEqual(signature["key_id"], hashlib.sha256(key.encode("utf-8")).hexdigest()[:16])
        # Everything before the signature line, joined by newline, exactly as sent.
        expected = hmac.new(
            key.encode("utf-8"), "\n".join(lines[:-1]).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        self.assertEqual(signature["signature"], expected, "the export does not match its own signature")
        # The key is a secret input, never an artifact field.
        self.assertNotIn(key, text, "the signing key must never appear in the export")

    def test_audit_export_rows_rehash_independently(self):
        """T-179: the rows carry enough to recompute the hash chain without
        calling back into the service, so a reader does not have to trust the
        `chain_state` line it was handed."""
        self.exercise_full_flow()
        status, _, text = http_text("GET", "/api/v1/audit/export", SYSTEM_ADMIN)
        self.assertEqual(status, 200)
        lines = [line for line in text.split("\n") if line]
        header = json.loads(lines[0])

        prev = "genesis"
        for line in lines[1 : header["rows"] + 1]:
            record = json.loads(line)
            # Rebuild the canonical hash input in the documented field order
            # (admin-api.md §7) from the exported row alone.
            canonical = json.dumps(
                {
                    "actor": {
                        "subject": record["actor_subject"],
                        "roles": json.loads(record["actor_roles"] or "[]"),
                    },
                    "org_id": record["org_id"],
                    "action": record["action"],
                    "resource": record["resource"],
                    "outcome": record["outcome"],
                    "request_id": record["request_id"],
                    "details": json.loads(record["details"] or "{}"),
                },
                separators=(",", ":"),
                ensure_ascii=False,
            )
            digest = hashlib.sha256((canonical + prev).encode("utf-8")).hexdigest()
            self.assertEqual(
                record["prev_hash"], prev, f"row {record['seq']} does not link to its predecessor"
            )
            self.assertEqual(
                record["entry_hash"],
                digest,
                f"row {record['seq']} does not hash to its recorded entry_hash",
            )
            prev = record["entry_hash"]

        self.assertEqual(prev, json.loads(lines[-2])["head_hash"], "recomputed head must match chain_state")

    def test_audit_export_needs_more_than_audit_read(self):
        """T-179/T-259: the GLOBAL export is system-admin only — reading the
        log is not enough, and neither is org_admin (org-scoped `audit.export`
        now) or security_admin."""
        for headers in (
            VIEWER,
            SECURITY_ADMIN,
            ORG_ADMIN,
            {"x-kiwi-subject": "e2e-anonymous"},
            {"x-kiwi-subject": "typo", "x-kiwi-roles": "org-admin,admin"},
        ):
            status, _, body = http_text("GET", "/api/v1/audit/export", headers)
            self.assertEqual(status, 403, f"export must refuse {headers}: {status} {body[:120]}")


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
        # Org-scoped reads bind the org (T-193/H2) — the platform headers
        # hold no org scope, so the scoped calls below carry it explicitly.
        bound = {"x-kiwi-subject": "e2e-admin", "x-kiwi-roles": "org_admin", "x-kiwi-org": org}
        status, scoped = http("GET", f"/api/v1/audit?org={org}&limit=1000", None, bound)
        self.assertEqual(status, 200, f"scoped audit read failed: {status} {scoped}")
        scoped = scoped["items"]
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


class T193Regression(AdminE2E):
    """T-193 regression guards over HTTP (admin-review-1 H1-H8 + M1-M7).

    Dialect-independent like TransportLeg: every property here must hold on
    SQLite and Postgres alike (H7 is exactly a case where they diverged).
    Tests are order-independent against the shared long-lived compose DB —
    unique stamps per run, presence assertions, never exact global counts.
    """

    # -- per-test fixtures ------------------------------------------------

    def fresh_org(self, headers=ORG_ADMIN):
        stamp = f"{int(time.time() * 1000)}-{os.getpid()}"
        return self.create_org(f"T193 {stamp}")

    def org_headers(self, role, org, subject="t193"):
        return {"x-kiwi-subject": subject, "x-kiwi-roles": role, "x-kiwi-org": org}

    def create_policy(self, org, headers):
        status, body = http(
            "POST",
            f"/api/v1/orgs/{org}/policies",
            {
                "name": "t193 policy",
                "enabled": True,
                "min_tls": "tls1.2",
                "external_recipients": "warn",
                "domain_rules": [{"domain": "blocked.invalid", "action": "block"}],
            },
            headers,
        )
        self.assertEqual(status, 201, f"create policy failed: {status} {body}")
        return body["id"]

    def live_backend(self):
        """The dialect the service actually opened (device rows need SQL)."""
        if service_dialect() == "sqlite":
            return SqliteBackend()
        return PostgresBackend()

    # -- H1: evaluate is authenticated ------------------------------------

    def test_h1_evaluate_requires_an_actor(self):
        org = self.fresh_org()
        bound = self.org_headers("org_admin", org)
        policy = self.create_policy(org, bound)
        body = {
            "direction": "outbound",
            "sender": "a@kiwi-test.invalid",
            "recipient": "b@blocked.invalid",
            "tlsVersion": "tls1.2",
        }
        # Pre-H1 the route discarded the actor: no headers meant a free
        # policy oracle plus an existence probe via the 404 path.
        status, err = http("POST", f"/api/v1/policies/{policy}/evaluate", body, {"x-kiwi-subject": "nobody"})
        self.assertEqual(status, 403, f"role-less evaluate must be refused: {status} {err}")
        self.assertEqual(err["error"]["code"], "auth.denied")

        other = self.fresh_org()
        status, _ = http(
            "POST", f"/api/v1/policies/{policy}/evaluate", body, self.org_headers("org_admin", other)
        )
        self.assertEqual(status, 403, "cross-org evaluate must be refused")

        status, verdict = http("POST", f"/api/v1/policies/{policy}/evaluate", body, bound)
        self.assertEqual(status, 200, f"own-org evaluate failed: {status} {verdict}")
        self.assertIn(verdict.get("verdict"), ("allow", "warn", "block"))

    # -- H2: fail-closed org scope -----------------------------------------

    def test_h2_org_scoped_call_without_org_header_is_denied(self):
        org = self.fresh_org()
        floater = {"x-kiwi-subject": "floater", "x-kiwi-roles": "security_admin"}
        status, err = http(
            "POST",
            f"/api/v1/orgs/{org}/policies",
            {"name": "floater", "enabled": True, "external_recipients": "allow", "domain_rules": []},
            floater,
        )
        self.assertEqual(status, 403, f"null-org actor must not hold org scope: {status} {err}")

    # -- H3: device revocation is org-scoped --------------------------------

    def test_h3_cross_org_revoke_is_denied(self):
        org_a = self.fresh_org()
        org_b = self.fresh_org()
        backend = self.live_backend()
        dev = backend.create_device(org_a, "t193 laptop")
        try:
            status, err = http(
                "POST", f"/api/v1/devices/{dev}/revoke", None, self.org_headers("org_admin", org_b)
            )
            self.assertEqual(status, 403, f"cross-org revoke must be refused: {status} {err}")
            self.assertFalse(backend.device_revoked(dev), "a denied revoke must not land")

            status, _ = http(
                "POST", f"/api/v1/devices/{dev}/revoke", None, self.org_headers("org_admin", org_a)
            )
            self.assertEqual(status, 200, "own-org revoke must work")
            self.assertTrue(backend.device_revoked(dev), "own-org revoke must land")
        finally:
            backend.delete_device(dev)

    # -- T-253: §14 device inventory (GET /orgs/{org}/devices) ---------------

    def test_t253_device_inventory_route(self):
        """Ratified wire shape, ordering, org scope, and the denial audit row."""
        org = self.fresh_org()
        other = self.fresh_org()
        bound = self.org_headers("org_admin", org)
        backend = self.live_backend()
        dev_a = backend.create_device(org, "e2e phone")
        dev_b = backend.create_device(org, "e2e laptop")
        stray = backend.create_device(other, "stray device")
        try:
            # Revoke one through the real route so revoked_at is populated.
            status, _ = http(
                "POST", f"/api/v1/devices/{dev_b}/revoke", None, self.org_headers("org_admin", org)
            )
            self.assertEqual(status, 200)

            status, body = http("GET", f"/api/v1/orgs/{org}/devices", None, bound)
            self.assertEqual(status, 200, f"inventory failed: {status} {body}")
            items = body["items"]
            ids = [i["id"] for i in items]
            # §14.1 total order: created_at ASC, id ASC (ids are random, so
            # verify the (created_at, id) pairs are monotonically sorted —
            # the id tie-breaker only orders same-millisecond rows).
            keys = [(i["created_at"], i["id"]) for i in items]
            self.assertEqual(keys, sorted(keys), "rows must arrive in created_at,id order")
            self.assertIn(dev_a, ids)
            self.assertIn(dev_b, ids)
            self.assertNotIn(stray, ids, "the other org's device leaked")
            for item in items:
                self.assertEqual(
                    sorted(item.keys()),
                    ["created_at", "id", "label", "org_id", "revoked", "revoked_at"],
                )
                self.assertEqual(item["org_id"], org)
                self.assertIn(item["revoked"], (0, 1))
            revoked = next(i for i in items if i["id"] == dev_b)
            self.assertEqual(revoked["revoked"], 1)
            self.assertIsInstance(revoked["revoked_at"], int, "revoked row must carry revoked_at")

            # Bounds: ?limit=1 yields one row; a non-decimal limit is a 400.
            status, one = http("GET", f"/api/v1/orgs/{org}/devices?limit=1", None, bound)
            self.assertEqual(status, 200)
            self.assertEqual(len(one["items"]), 1)
            status, err = http("GET", f"/api/v1/orgs/{org}/devices?limit=abc", None, bound)
            self.assertEqual(status, 400)
            self.assertEqual(err["error"]["code"], "validation.failed")

            # Scope: cross-org and null-org are denied AND audited (§14.3).
            status, err = http(
                "GET", f"/api/v1/orgs/{org}/devices", None, self.org_headers("org_admin", other)
            )
            self.assertEqual(status, 403, f"cross-org read must be refused: {status} {err}")
            self.assertEqual(err["error"]["details"]["permission"], "device.read")
            status, _ = http("GET", f"/api/v1/orgs/{org}/devices", None, ORG_ADMIN)
            self.assertEqual(status, 403, "null-org actor holds no org scope")

            audit = self.fetch_audit(f"?org={org}&limit=1000")
            denials = [
                r for r in audit["items"]
                if r["action"] == "device.list" and r["outcome"] == "denied"
            ]
            self.assertGreaterEqual(len(denials), 2, "denied device reads must be audited")
            for row in denials:
                self.assertEqual(json.loads(row["details"]).get("permission"), "device.read")

            # Unknown-but-valid org id: 200 with an empty list (§14.1,
            # consistent with listUsers — not a 404).
            ghost = "org-e2e-nonexistent"
            status, body = http(
                "GET", f"/api/v1/orgs/{ghost}/devices", None, self.org_headers("org_admin", ghost)
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["items"], [])
        finally:
            backend.delete_device(dev_a)
            backend.delete_device(dev_b)
            backend.delete_device(stray)

    def test_t259_admin_drift_fixes(self):
        """T-259 (ADM-T250-*): org-scoped audit export, denial audit on reads,
        full audit records, honest verify window, and ghost-org not.found."""
        org = self.fresh_org()
        bound = self.org_headers("org_admin", org)
        other = self.fresh_org()
        bound_other = self.org_headers("org_admin", other, subject="t259-other")

        # -- ADM-T250-07: org-scoped export serves only the path org's rows --
        status, ctype, text = http_text("GET", f"/api/v1/orgs/{org}/audit/export", bound)
        self.assertEqual(status, 200, f"org export failed: {status} {text[:200]}")
        self.assertIn("application/x-ndjson", ctype)
        lines = [l for l in text.split("\n") if l]
        header = json.loads(lines[0])
        self.assertEqual(header["version"], "kiwi.audit-export-org/1")
        self.assertEqual(header["scope"], "org")
        self.assertEqual(header["org_id"], org)
        # Trailer is scope_state — never a whole-chain claim.
        scope = json.loads(lines[-2])
        self.assertEqual(scope["type"], "scope_state")
        self.assertEqual(scope["chain_claim"], "none")
        self.assertNotIn('"chain_state"', text)
        for line in lines[1:-2]:
            self.assertEqual(json.loads(line)["org_id"], org, "a foreign-org row leaked")

        # Cross-org + the platform-only system-admin are both refused.
        status, _, _ = http_text("GET", f"/api/v1/orgs/{org}/audit/export", bound_other)
        self.assertEqual(status, 403, "a foreign org's export must deny")
        status, _, _ = http_text("GET", f"/api/v1/orgs/{org}/audit/export", SYSTEM_ADMIN)
        self.assertEqual(status, 403, "system-admin is global-only, not org-scoped")

        # -- ADM-T250-02: audit rows carry the full record --
        status, body = http("GET", "/api/v1/audit?limit=5", None, ORG_ADMIN)
        self.assertEqual(status, 200)
        row = body["items"][0]
        for key in ("seq", "actor_roles", "org_id", "resource", "request_id", "prev_hash", "entry_hash"):
            self.assertIn(key, row, f"audit row missing {key}")

        # -- ADM-T250-03: a truncated verify window cannot claim validity ------
        status, body = http("GET", "/api/v1/audit/verify?limit=1", None, ORG_ADMIN)
        self.assertEqual(status, 200)
        self.assertFalse(body["complete"], "a 1-row window must report complete:false")
        self.assertFalse(body["valid"], "a truncated window must not attest the chain")

        # -- ADM-T250-04: a refused READ is audited ----------------------------
        status, _ = http("GET", f"/api/v1/orgs/{org}/users", None, bound_other)
        self.assertEqual(status, 403)
        status, body = http("GET", f"/api/v1/audit?org={org}&limit=100", None, bound)
        denied = [r for r in body["items"] if r["action"] == "user.list" and r["outcome"] == "denied"]
        self.assertTrue(denied, "the cross-org read denial must be audited")

        # -- ADM-T250-13: writes on a ghost org are 404, not an FK 500 --------
        ghost = "org-00000000-0000-0000-0000-000000000000"
        ghost_headers = {"x-kiwi-subject": "t259-ghost", "x-kiwi-roles": "org_admin", "x-kiwi-org": ghost}
        status, err = http("POST", f"/api/v1/orgs/{ghost}/users", {"email": "g@x.test"}, ghost_headers)
        self.assertEqual(status, 404, f"ghost-org createUser must be 404: {status} {err}")
        self.assertEqual(err["error"]["code"], "not.found")

        # -- ADM-T250-01/12: canonical wire shapes ----------------------------
        status, body = http(
            "POST", f"/api/v1/orgs/{org}/policies",
            {"name": "t259", "enabled": True, "min_tls": None,
             "external_recipients": "allow", "domain_rules": []},
            bound,
        )
        self.assertEqual(status, 201)
        pid = body["id"]
        status, body = http("GET", f"/api/v1/orgs/{org}/policies", None, bound)
        p = body["items"][0]
        self.assertIn("org_id", p)
        self.assertIn("min_tls", p)
        self.assertNotIn("minTls", p)
        status, body = http(
            "POST", f"/api/v1/policies/{pid}/evaluate",
            {"direction": "outbound", "sender": "a@x.test", "recipient": "b@y.test", "tlsVersion": None},
            bound,
        )
        self.assertEqual(body["policyId"], pid, "evaluate must emit the canonical policyId field")

    def test_h4_unfiltered_reads_stay_inside_the_callers_org(self):
        org_a = self.fresh_org()
        org_b = self.fresh_org()
        bound_a = self.org_headers("org_admin", org_a)
        bound_b = self.org_headers("org_admin", org_b)
        viewer_a = self.org_headers("viewer", org_a, subject="t193-viewer")
        for org, headers in ((org_a, bound_a), (org_b, bound_b)):
            status, _ = http(
                "POST",
                "/api/v1/mailflow/events",
                {
                    "direction": "outbound",
                    "sender": f"a@{org}.kiwi-test.invalid",
                    "recipient": "b@blocked.invalid",
                    "ts": int(time.time() * 1000),
                    "tls_version": "tls1.2",
                    "security_status": "clean",
                    "policy_verdict": "allow",
                    "org_id": org,
                },
                headers,
            )
            self.assertEqual(status, 201)

        status, body = http("GET", "/api/v1/mailflow/events?limit=100", None, viewer_a)
        self.assertEqual(status, 200)
        self.assertTrue(body["items"], "own-org rows must come back")
        for event in body["items"]:
            self.assertEqual(event["org_id"], org_a, "unfiltered read leaked another org")

        status, _ = http("GET", f"/api/v1/mailflow/events?org={org_b}&limit=100", None, viewer_a)
        self.assertEqual(status, 403, "explicit cross-org widening must be refused")

        status, unfiltered = http("GET", "/api/v1/audit?limit=1000", None, viewer_a)
        self.assertEqual(status, 200)
        status, scoped = http("GET", f"/api/v1/audit?org={org_a}&limit=1000", None, viewer_a)
        self.assertEqual(status, 200)
        self.assertEqual(
            [r["seq"] for r in unfiltered["items"]],
            [r["seq"] for r in scoped["items"]],
            "unfiltered audit read must equal the caller's own-org slice",
        )
        status, _ = http("GET", f"/api/v1/audit?org={org_b}&limit=1000", None, viewer_a)
        self.assertEqual(status, 403)

    # -- H5: createOrg requires org.create -----------------------------------

    def test_h5_viewer_cannot_create_orgs(self):
        status, err = http(
            "POST", "/api/v1/orgs", {"name": "viewer-org"}, {"x-kiwi-subject": "v", "x-kiwi-roles": "viewer"}
        )
        self.assertEqual(status, 403, f"viewer createOrg must be refused: {status} {err}")

    # -- H6: concurrent appends stay gapless ----------------------------------

    def test_h6_parallel_burst_appends_without_loss(self):
        """Ten concurrent mutations serialize: every request succeeds and the
        chain still verifies (the H6 failure mode was a 500 + a lost row)."""
        import concurrent.futures

        org = self.fresh_org()
        bound = self.org_headers("org_admin", org)
        stamp = int(time.time() * 1000)

        def add_user(i):
            return http(
                "POST",
                f"/api/v1/orgs/{org}/users",
                {"email": f"burst{stamp}-{i}@kiwi-test.invalid"},
                bound,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(add_user, range(10)))
        for status, body in results:
            self.assertEqual(status, 201, f"concurrent append lost a row: {status} {body}")
        self.assert_chain_valid("chain must verify after a concurrent burst")

    # -- H7: UNIQUE(org_id, email) holds on this dialect -----------------------

    def test_h7_duplicate_email_is_rejected(self):
        """H7 was a Postgres-only gap (SQLite shipped UNIQUE, PG a plain
        index): the same double-create must 409 on whichever dialect is live."""
        org = self.fresh_org()
        bound = self.org_headers("org_admin", org)
        email = f"dup-{int(time.time() * 1000)}@kiwi-test.invalid"
        status, _ = http("POST", f"/api/v1/orgs/{org}/users", {"email": email}, bound)
        self.assertEqual(status, 201)
        status, err = http("POST", f"/api/v1/orgs/{org}/users", {"email": email}, bound)
        self.assertEqual(status, 409, f"duplicate email must conflict: {status} {err}")
        self.assertEqual(err["error"]["code"], "conflict")

    # -- H8: verify never attests an empty window -------------------------------

    def test_h8_verify_floor(self):
        for query in ("limit=0", "limit=-1"):
            status, err = http("GET", f"/api/v1/audit/verify?{query}", None, ORG_ADMIN)
            self.assertEqual(status, 400, f"verify?{query} must be refused: {status} {err}")
            self.assertEqual(err["error"]["code"], "validation.failed")
        status, body = http("GET", "/api/v1/audit/verify?limit=10000", None, ORG_ADMIN)
        self.assertEqual(status, 200)
        self.assertTrue(body["valid"])
        self.assertGreater(body["checked"], 0, "verify must actually check rows")

    # -- M1: one timestamp unit (milliseconds) ------------------------------------

    def test_m1_service_timestamps_are_milliseconds(self):
        """Contract §4 declares Unix milliseconds; rows stamped in seconds
        would be off by 1000x against every since/until filter."""
        body = self.fetch_audit("?limit=50")
        self.assertTrue(body["items"], "no audit rows to inspect")
        for row in body["items"]:
            self.assertGreater(row["ts"], 10_000_000_000, f"audit ts not ms-scale: {row['ts']}")

    # -- M6: grantRole is membership-checked ---------------------------------------

    def test_m6_outsider_grant_is_404(self):
        org_a = self.fresh_org()
        org_b = self.fresh_org()
        bound_a = self.org_headers("org_admin", org_a)
        bound_b = self.org_headers("org_admin", org_b)
        status, user = http(
            "POST", f"/api/v1/orgs/{org_a}/users", {"email": f"out-{int(time.time() * 1000)}@kiwi-test.invalid"}, bound_a
        )
        self.assertEqual(status, 201)
        status, err = http(
            "PUT", f"/api/v1/orgs/{org_b}/users/{user['id']}/role", {"role": "viewer"}, bound_b
        )
        self.assertEqual(status, 404, f"outsider grant must be 404: {status} {err}")

    # -- M7: listings are bounded -----------------------------------------------------

    def test_m7_listings_honor_limit(self):
        org = self.fresh_org()
        bound = self.org_headers("org_admin", org)
        status, body = http("GET", f"/api/v1/orgs/{org}/users?limit=1", None, bound)
        self.assertEqual(status, 200)
        self.assertLessEqual(len(body["items"]), 1)
        status, body = http("GET", f"/api/v1/orgs/{org}/policies?limit=1", None, bound)
        self.assertEqual(status, 200)
        self.assertLessEqual(len(body["items"]), 1)


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
