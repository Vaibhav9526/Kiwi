/** Localhost HTTP transport tests (T-134): contract wire mapping over services. */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHmac } from "node:crypto";
import { startServer, type ServerHandle } from "../src/server.js";
import { AUDIT_EXPORT_VERSION } from "../src/audit/export.js";
import { makeTempDbPath } from "./helpers/db.js";

/** Pinned so the export tests can recompute the HMAC hermetically. */
const EXPORT_KEY = "unit-test-export-key";

let handle: ServerHandle;
let base: string;

interface ApiResponse {
  status: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json: any;
}

async function api(path: string, opts: { method?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<ApiResponse> {
  const init: RequestInit = {
    method: opts.method ?? "GET",
    headers: { "content-type": "application/json", ...(opts.headers ?? {}) },
  };
  if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  const res = await fetch(`${base}${path}`, init);
  return { status: res.status, json: (await res.json()) as unknown };
}

/** Raw-text fetch, for responses that are not JSON (the NDJSON export). */
async function apiRaw(path: string, headers: Record<string, string>): Promise<{ status: number; contentType: string; text: string }> {
  const res = await fetch(`${base}${path}`, { headers });
  return { status: res.status, contentType: res.headers.get("content-type") ?? "", text: await res.text() };
}

const adminHeaders = { "x-kiwi-subject": "tester", "x-kiwi-roles": "org_admin" };
const viewerHeaders = { "x-kiwi-subject": "viewer", "x-kiwi-roles": "viewer", "x-kiwi-org": "__ORG__" };
// Org-bound admin (T-193/H2): null-org actors hold no org scope, so every
// org-scoped call below binds the org. `adminHeaders` stays platform-null
// for the bootstrap + whole-log reads that are platform acts by design.
const boundHeaders = { "x-kiwi-subject": "tester", "x-kiwi-roles": "org_admin", "x-kiwi-org": "__ORG__" };

let orgId = "";

beforeAll(async () => {
  // `databaseUrl: null` pins the SQLite dialect so the suite never follows an
  // ambient DATABASE_URL into a real Postgres instance; `auditExportKey` is
  // pinned for the same reason so the export signature is reproducible.
  handle = await startServer({ dbPath: makeTempDbPath(), databaseUrl: null, auditExportKey: EXPORT_KEY, port: 0 });
  base = `http://127.0.0.1:${handle.port}`;
  const created = await api("/api/v1/orgs", { method: "POST", body: { name: "http.test" }, headers: adminHeaders });
  expect(created.status).toBe(201);
  orgId = (created.json as { id: string }).id as string;
  viewerHeaders["x-kiwi-org"] = orgId;
  boundHeaders["x-kiwi-org"] = orgId;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => handle.server.close((e) => (e ? reject(e) : resolve())));
  await handle.container.close();
});

describe("server transport", () => {
  it("serves healthz", async () => {
    const r = await api("/healthz");
    expect(r.status).toBe(200);
    expect(r.json.status).toBe("ok");
  });

  it("manages users and roles", async () => {
    const created = await api(`/api/v1/orgs/${orgId}/users`, {
      method: "POST",
      body: { email: "http-user@http.test" },
      headers: boundHeaders,
    });
    expect(created.status).toBe(201);
    const userId = (created.json as { id: string }).id as string;

    const granted = await api(`/api/v1/orgs/${orgId}/users/${userId}/role`, {
      method: "PUT",
      body: { role: "viewer" },
      headers: boundHeaders,
    });
    expect(granted.status).toBe(200);

    const listed = await api(`/api/v1/orgs/${orgId}/users`, { headers: boundHeaders });
    expect(listed.status).toBe(200);
    const row = (listed.json.items as { email: string; roles: string[] }[]).find((u) => u.email === "http-user@http.test");
    expect(row?.roles).toEqual(["viewer"]);
  });

  it("creates, lists, and evaluates policies including the outbound bridge", async () => {
    const created = await api(`/api/v1/orgs/${orgId}/policies`, {
      method: "POST",
      body: {
        name: "http-default",
        enabled: true,
        min_tls: "tls1.2",
        external_recipients: "warn",
        domain_rules: [{ domain: "partner.example", action: "allow" }],
      },
      headers: boundHeaders,
    });
    expect(created.status).toBe(201);
    const policyId = (created.json as { id: string }).id as string;

    const listed = await api(`/api/v1/orgs/${orgId}/policies`, { headers: boundHeaders });
    expect(listed.status).toBe(200);
    expect((listed.json.items as { id: string }[]).some((p) => p.id === policyId)).toBe(true);

    const single = await api(`/api/v1/policies/${policyId}/evaluate`, {
      method: "POST",
      body: { direction: "outbound", sender: "a@http.test", recipient: "b@partner.example", tlsVersion: "tls1.3" },
      headers: boundHeaders,
    });
    expect(single.json.verdict).toBe("allow");

    const bridge = await api(`/api/v1/orgs/${orgId}/policies/evaluate-outbound`, {
      method: "POST",
      body: { sender: "a@http.test", recipients: ["b@partner.example", "c@stranger.test"], tlsVersion: "tls1.0" },
      headers: boundHeaders,
    });
    expect(bridge.json.overall).toBe("block");
    expect((bridge.json.results as { verdict: string }[]).map((r) => r.verdict)).toEqual(["block", "block"]);
  });

  it("ingests and queries mailflow events", async () => {
    const ingested = await api("/api/v1/mailflow/events", {
      method: "POST",
      body: {
        direction: "outbound",
        sender: "a@http.test",
        recipient: "b@partner.example",
        ts: 7000,
        message_id: null,
        tls_version: "tls1.3",
        security_status: "clean",
        policy_verdict: "allow",
        org_id: orgId,
      },
      headers: boundHeaders,
    });
    expect(ingested.status).toBe(201);

    const queried = await api(`/api/v1/mailflow/events?org=${orgId}&limit=10`, { headers: boundHeaders });
    expect(queried.status).toBe(200);
    expect((queried.json.items as { recipient: string }[]).some((e) => e.recipient === "b@partner.example")).toBe(true);
  });

  it("reads and verifies the audit log", async () => {
    const q = await api(`/api/v1/audit?limit=5`, { headers: boundHeaders });
    expect(q.status).toBe(200);
    expect(Array.isArray(q.json.items)).toBe(true);
    const v = await api(`/api/v1/audit/verify?limit=1000`, { headers: boundHeaders });
    expect(v.json.valid).toBe(true);
  });

  it("denies unauthorized writes with the contract error shape", async () => {
    const r = await api(`/api/v1/orgs/${orgId}/policies`, {
      method: "POST",
      body: { name: "nope", enabled: true, min_tls: null, external_recipients: "allow", domain_rules: [] },
      headers: viewerHeaders,
    });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe("auth.denied");
  });

  it("rejects malformed input and unknown routes", async () => {
    const bad = await api(`/api/v1/orgs/${orgId}/policies`, {
      method: "POST",
      body: { name: "bad", enabled: true, min_tls: "TLS9", external_recipients: "allow", domain_rules: [] },
      headers: boundHeaders,
    });
    expect(bad.status).toBe(400);
    expect(bad.json.error.code).toBe("validation.failed");

    const missing = await api("/api/v1/nope", { headers: boundHeaders });
    expect(missing.status).toBe(404);
    expect(missing.json.error.code).toBe("not.found");
  });

  it("fails closed when the roles header is absent or unusable", async () => {
    // No `x-kiwi-roles` at all: unauthenticated, so refused — never promoted
    // to a default org_admin.
    const anonymous = await api("/api/v1/orgs", {
      method: "POST",
      body: { name: "should-not-exist.test" },
      headers: { "x-kiwi-subject": "anonymous" },
    });
    expect(anonymous.status).toBe(403);
    expect(anonymous.json.error.code).toBe("auth.denied");

    // A role name that parses to nothing is equally not a role.
    const typo = await api("/api/v1/orgs", {
      method: "POST",
      body: { name: "should-not-exist.test" },
      headers: { "x-kiwi-subject": "typo", "x-kiwi-roles": "org-admin,admin,superuser" },
    });
    expect(typo.status).toBe(403);
  });

  it("requires audit.read to read or verify the audit log", async () => {
    const anonymous = await api("/api/v1/audit?limit=5", { headers: { "x-kiwi-subject": "anonymous" } });
    expect(anonymous.status).toBe(403);

    const anonymousVerify = await api("/api/v1/audit/verify", { headers: { "x-kiwi-subject": "anonymous" } });
    expect(anonymousVerify.status).toBe(403);

    // A viewer holds audit.read, so the read succeeds.
    const allowed = await api("/api/v1/audit?limit=5", { headers: viewerHeaders });
    expect(allowed.status).toBe(200);
  });

  it("scopes the audit log to one org with ?org=", async () => {
    const all = await api(`/api/v1/audit?limit=1000`, { headers: adminHeaders });
    expect(all.status).toBe(200);
    // `org.create` is audited with a NULL org_id (it is a platform-level act),
    // so it is the marker for "rows belonging to no org".
    expect((all.json.items as { action: string }[]).some((r) => r.action === "org.create")).toBe(true);

    const scoped = await api(`/api/v1/audit?org=${orgId}&limit=1000`, { headers: boundHeaders });
    expect(scoped.status).toBe(200);
    const scopedItems = scoped.json.items as { action: string; seq: number }[];
    // The filter must actually narrow the result — this is the regression
    // guard for the parameter the server accepted but AuditService ignored.
    expect(scopedItems.length).toBeLessThan((all.json.items as unknown[]).length);
    expect(scopedItems.some((r) => r.action === "org.create")).toBe(false);
    // Rows that ARE in the org come through.
    expect(scopedItems.some((r) => r.action === "policy.create")).toBe(true);
  });

  it("exports the audit log as signed NDJSON", async () => {
    const r = await apiRaw("/api/v1/audit/export", adminHeaders);
    expect(r.status).toBe(200);
    // NDJSON, not JSON — a JSON response would mean the newlines survived as
    // escapes and the line structure was destroyed.
    expect(r.contentType).toContain("application/x-ndjson");

    const lines = r.text.split("\n").filter((l) => l.length > 0);
    const header = JSON.parse(lines[0] ?? "") as { type: string; version: string; rows: number; first_seq: number };
    expect(header.type).toBe("header");
    expect(header.version).toBe(AUDIT_EXPORT_VERSION);
    expect(header.first_seq).toBe(1);
    // header + one line per record + chain_state + signature
    expect(header.rows).toBe(lines.length - 3);

    const state = JSON.parse(lines[lines.length - 2] ?? "") as { type: string; valid: boolean; error: string | null };
    expect(state.type).toBe("chain_state");
    expect(state.valid).toBe(true);
    expect(state.error).toBeNull();

    const sig = JSON.parse(lines[lines.length - 1] ?? "") as {
      type: string;
      alg: string;
      signed: boolean;
      signature: string;
      covers_through: number;
    };
    expect(sig.type).toBe("signature");
    expect(sig.alg).toBe("hmac-sha256");
    expect(sig.signed).toBe(true);
    expect(sig.covers_through).toBe(lines.length - 1);
    // Recompute the HMAC exactly as an outside verifier would.
    expect(sig.signature).toBe(createHmac("sha256", EXPORT_KEY).update(lines.slice(0, -1).join("\n")).digest("hex"));
    // The key itself never appears in the artifact.
    expect(r.text).not.toContain(EXPORT_KEY);
  });

  it("refuses audit export for everyone but org_admin", async () => {
    // `audit.read` is broad (all three roles hold it) and `audit.export` is not:
    // this is the test that keeps the two from being conflated.
    const securityAdmin = { "x-kiwi-subject": "sec", "x-kiwi-roles": "security_admin" };
    for (const headers of [viewerHeaders, securityAdmin, { "x-kiwi-subject": "anonymous" }]) {
      const r = await apiRaw("/api/v1/audit/export", headers);
      expect(r.status).toBe(403);
    }
  });
});

describe("T-193 HTTP regression guards", () => {
  it("H1: policy evaluation requires an actor (no headers, or a role-less caller, is 403)", async () => {
    const listed = await api(`/api/v1/orgs/${orgId}/policies`, { headers: boundHeaders });
    const policyId = (listed.json.items as { id: string }[])[0]!.id;
    const body = { direction: "outbound", sender: "a@http.test", recipient: "b@partner.example", tlsVersion: "tls1.3" };
    // Pre-H1 this route discarded the actor entirely — no headers meant a
    // free policy oracle. Now it is a permission-checked, audited read.
    const naked = await api(`/api/v1/policies/${policyId}/evaluate`, {
      method: "POST",
      body,
      headers: { "x-kiwi-subject": "nobody" },
    });
    expect(naked.status).toBe(403);
    expect(naked.json.error.code).toBe("auth.denied");
    // Cross-org evaluation is equally refused.
    const other = await api("/api/v1/orgs", { method: "POST", body: { name: "other-http.test" }, headers: adminHeaders });
    const otherOrg = (other.json as { id: string }).id as string;
    const cross = await api(`/api/v1/policies/${policyId}/evaluate`, {
      method: "POST",
      body,
      headers: { "x-kiwi-subject": "tester", "x-kiwi-roles": "org_admin", "x-kiwi-org": otherOrg },
    });
    expect(cross.status).toBe(403);
  });

  it("H2: an org-scoped call without x-kiwi-org is denied, not global", async () => {
    // A security_admin role with NO org binding must not exercise org scope.
    const floater = { "x-kiwi-subject": "floater", "x-kiwi-roles": "security_admin" };
    const r = await api(`/api/v1/orgs/${orgId}/policies`, {
      method: "POST",
      body: { name: "floater", enabled: true, min_tls: null, external_recipients: "allow", domain_rules: [] },
      headers: floater,
    });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe("auth.denied");
  });

  it("H4: an org-bound mailflow read without ?org= stays inside its own org", async () => {
    const r = await api(`/api/v1/mailflow/events?limit=50`, { headers: viewerHeaders });
    expect(r.status).toBe(200);
    const items = r.json.items as { org_id: string | null }[];
    expect(items.length).toBeGreaterThan(0);
    expect(items.every((e) => e.org_id === orgId)).toBe(true);
  });

  it("H5: viewers cannot create orgs; org_admin can", async () => {
    const denied = await api("/api/v1/orgs", {
      method: "POST",
      body: { name: "viewer-org.test" },
      headers: { "x-kiwi-subject": "v", "x-kiwi-roles": "viewer" },
    });
    expect(denied.status).toBe(403);
    const allowed = await api("/api/v1/orgs", {
      method: "POST",
      body: { name: "h5-http.test" },
      headers: adminHeaders,
    });
    expect(allowed.status).toBe(201);
  });

  it("H8: verify?limit=0 is a 400, never an attested empty chain", async () => {
    for (const q of ["limit=0", "limit=-1"]) {
      const r = await api(`/api/v1/audit/verify?${q}`, { headers: boundHeaders });
      expect(r.status).toBe(400);
      expect(r.json.error.code).toBe("validation.failed");
    }
    const v = await api(`/api/v1/audit/verify?limit=1000`, { headers: boundHeaders });
    expect(v.json.valid).toBe(true);
    expect(v.json.checked).toBeGreaterThan(0);
  });

  it("M5+M6: duplicate email is a 409 conflict; outsider grant is a 404", async () => {
    const email = `dup-${Date.now()}@http.test`;
    const first = await api(`/api/v1/orgs/${orgId}/users`, {
      method: "POST",
      body: { email },
      headers: boundHeaders,
    });
    expect(first.status).toBe(201);
    const second = await api(`/api/v1/orgs/${orgId}/users`, {
      method: "POST",
      body: { email },
      headers: boundHeaders,
    });
    expect(second.status).toBe(409);
    expect(second.json.error.code).toBe("conflict");
    const outsider = await api(`/api/v1/orgs/org-nope/users/${(first.json as { id: string }).id}/role`, {
      method: "PUT",
      body: { role: "viewer" },
      headers: { "x-kiwi-subject": "tester", "x-kiwi-roles": "org_admin", "x-kiwi-org": "org-nope" },
    });
    // The user belongs to the real org, not the actor's path org: the grant
    // targets (user, org) jointly, so this is a 404 — never a cross-org
    // role row, never a constraint-name 500.
    expect(outsider.status).toBe(404);
  });

  it("M7: user listing honors ?limit=", async () => {
    const r = await api(`/api/v1/orgs/${orgId}/users?limit=1`, { headers: boundHeaders });
    expect(r.status).toBe(200);
    expect((r.json.items as unknown[]).length).toBeLessThanOrEqual(1);
  });
});
