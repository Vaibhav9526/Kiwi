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
// §13 (T-259): the platform role — the only identity the GLOBAL audit
// export accepts. Unbound to any org.
const systemAdminHeaders = { "x-kiwi-subject": "sysadmin", "x-kiwi-roles": "system-admin" };
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
    const r = await apiRaw("/api/v1/audit/export", systemAdminHeaders);
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

  it("refuses the global audit export for everyone but system-admin", async () => {
    // §13/T-259: org_admin holds `audit.export` only org-scoped — the global
    // whole-chain route denies it too. `audit.read` stays broad.
    const securityAdmin = { "x-kiwi-subject": "sec", "x-kiwi-roles": "security_admin" };
    for (const headers of [viewerHeaders, securityAdmin, adminHeaders, boundHeaders, { "x-kiwi-subject": "anonymous" }]) {
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

/** T-253 — §14 device inventory: org-scoped read, denial audit, bounds. */
describe("device inventory (T-253, §14)", () => {
  let devOrg = "";
  let d1Id = "";
  let d2Id = "";
  let d3Id = "";
  const seedAdmin = () => ({ subject: "seeder", roles: ["org_admin" as const], orgId: devOrg });
  const devHeaders = { "x-kiwi-subject": "devadmin", "x-kiwi-roles": "org_admin", "x-kiwi-org": "" };

  beforeAll(async () => {
    const created = await api("/api/v1/orgs", { method: "POST", body: { name: "devices.test" }, headers: adminHeaders });
    expect(created.status).toBe(201);
    devOrg = created.json.id as string;
    devHeaders["x-kiwi-org"] = devOrg;

    // Seed through the service (there is deliberately no create route —
    // §14.6); created_at values are pinned so ordering is deterministic.
    const d1 = await handle.container.orgs.createDevice(seedAdmin(), devOrg, "Pixel 8", 1000);
    const d2 = await handle.container.orgs.createDevice(seedAdmin(), devOrg, "Workstation", 2000);
    const d3 = await handle.container.orgs.createDevice(seedAdmin(), devOrg, "Key2", 2000); // same ms as d2 — id tie-breaker
    await handle.container.orgs.revokeDevice(seedAdmin(), d2.id, 3000);
    d1Id = d1.id;
    d2Id = d2.id;
    d3Id = d3.id;
  });

  it("serves the org-scoped list with the ratified wire shape", async () => {

    const r = await api(`/api/v1/orgs/${devOrg}/devices`, { headers: devHeaders });
    expect(r.status).toBe(200);
    const items = r.json.items as { id: string; org_id: string; label: string; revoked: number; revoked_at: number | null; created_at: number }[];
    expect(items.length).toBe(3);
    for (const it of items) {
      expect(Object.keys(it).sort()).toEqual(["created_at", "id", "label", "org_id", "revoked", "revoked_at"]);
      expect(it.org_id).toBe(devOrg);
      expect(typeof it.revoked).toBe("number"); // integer 0|1, never boolean
    }
    // created_at ASC, id ASC — the two same-millisecond rows order by id.
    expect(items[0]!.id).toBe(d1Id);
    const tail = [d2Id, d3Id].sort();
    expect([items[1]!.id, items[2]!.id]).toEqual(tail);
    // Revoked projection: real revoked_at column, never fabricated.
    const revoked = items.find((i) => i.id === d2Id)!;
    expect(revoked.revoked).toBe(1);
    expect(revoked.revoked_at).toBe(3000);
  });

  it("honors limit bounds (default 50, clamp 1..=500, decimal grammar)", async () => {
    const all = await api(`/api/v1/orgs/${devOrg}/devices`, { headers: devHeaders });
    expect(all.status).toBe(200);
    expect((all.json.items as unknown[]).length).toBe(3);

    const one = await api(`/api/v1/orgs/${devOrg}/devices?limit=1`, { headers: devHeaders });
    expect((one.json.items as unknown[]).length).toBe(1);

    const over = await api(`/api/v1/orgs/${devOrg}/devices?limit=99999`, { headers: devHeaders });
    expect(over.status).toBe(200); // clamped to 500, not an error
    expect((over.json.items as unknown[]).length).toBe(3);

    const zero = await api(`/api/v1/orgs/${devOrg}/devices?limit=0`, { headers: devHeaders });
    expect(zero.status).toBe(200); // clamped to 1
    expect((zero.json.items as unknown[]).length).toBe(1);

    const bad = await api(`/api/v1/orgs/${devOrg}/devices?limit=1e3`, { headers: devHeaders });
    expect(bad.status).toBe(400);
    expect(bad.json.error.code).toBe("validation.failed");
  });

  it("returns 200 {items:[]} for an unknown but valid org id", async () => {
    // §14.1: unknown org is an empty list, consistent with listUsers —
    // a 404 for unknown orgs is a separate deferred contract decision.
    const r = await api("/api/v1/orgs/org-00000000-0000-4000-8000-000000000000/devices", {
      headers: { "x-kiwi-subject": "nope", "x-kiwi-roles": "org_admin", "x-kiwi-org": "org-00000000-0000-4000-8000-000000000000" },
    });
    expect(r.status).toBe(200);
    expect(r.json.items).toEqual([]);
  });

  it("denies cross-org and null-org reads, auditing each denial", async () => {
    // Cross-org: actor bound to the first suite org reads the devices org.
    const cross = await api(`/api/v1/orgs/${devOrg}/devices`, { headers: boundHeaders });
    expect(cross.status).toBe(403);
    expect(cross.json.error.code).toBe("auth.denied");
    expect(cross.json.error.details.permission).toBe("device.read");

    // Null-org actor: no org binding → fail-closed denial on any org path.
    const nullOrg = await api(`/api/v1/orgs/${devOrg}/devices`, { headers: adminHeaders });
    expect(nullOrg.status).toBe(403);

    // §14.3 fixed row: action device.list, resource+org_id = path org,
    // outcome denied, details.permission, request_id null — the service
    // query projection omits resource/org_id (ADM-T250-02), so assert on
    // the raw audit_log row via the db facade.
    const denials = handle.container.db!.all(
      "SELECT resource, org_id, request_id, details, ts FROM audit_log WHERE action = 'device.list' AND outcome = 'denied'",
    ) as { resource: string; org_id: string; request_id: string | null; details: string; ts: number }[];
    expect(denials.length).toBeGreaterThanOrEqual(2);
    for (const d of denials) {
      expect(d.resource).toBe(devOrg);
      expect(d.org_id).toBe(devOrg);
      expect(d.request_id).toBeNull();
      expect(JSON.parse(d.details).permission).toBe("device.read");
      expect(Number.isSafeInteger(d.ts)).toBe(true);
    }
  });

  it("rejects a malformed path id and never merges duplicate labels", async () => {
    const bad = await api(`/api/v1/orgs/not!!valid/devices`, { headers: devHeaders });
    expect(bad.status).toBe(400);
    expect(bad.json.error.code).toBe("validation.failed");

    // §14.1: normalized-duplicate labels are a 409 rule for future create
    // paths — the read path returns both rows, never canonicalizes.
    await handle.container.orgs.createDevice(seedAdmin(), devOrg, "Dup Phone", 4000);
    await handle.container.orgs.createDevice(seedAdmin(), devOrg, "dup phone", 4001);
    const r = await api(`/api/v1/orgs/${devOrg}/devices`, { headers: devHeaders });
    const labels = (r.json.items as { label: string }[]).map((i) => i.label);
    expect(labels.filter((l) => l.toLowerCase() === "dup phone").length).toBe(2);
  });
});

describe("admin-drift fixes (T-259, ADM-T250-*)", () => {
  it("evaluates a single policy with the canonical `policyId` field (ADM-T250-12/13)", async () => {
    const created = await api(`/api/v1/orgs/${orgId}/policies`, {
      method: "POST",
      body: {
        name: "t259-eval",
        enabled: true,
        min_tls: null,
        external_recipients: "allow",
        domain_rules: [],
      },
      headers: boundHeaders,
    });
    expect(created.status).toBe(201);
    const pid = (created.json as { id: string }).id;
    const single = await api(`/api/v1/policies/${pid}/evaluate`, {
      method: "POST",
      body: { direction: "outbound", sender: "a@http.test", recipient: "b@x.test", tlsVersion: null },
      headers: boundHeaders,
    });
    expect(single.status).toBe(200);
    // One canonical name across single-evaluate and the §10 outbound bridge.
    expect(single.json).toHaveProperty("policyId", pid);
    expect(single.json).not.toHaveProperty("evaluatedPolicyId");
  });

  it("lists policies as the full §5.1 snake_case PolicyObject (ADM-T250-01)", async () => {
    const listed = await api(`/api/v1/orgs/${orgId}/policies`, { headers: boundHeaders });
    expect(listed.status).toBe(200);
    const items = listed.json.items as Record<string, unknown>[];
    expect(items.length).toBeGreaterThan(0);
    const p = items[0]!;
    for (const key of ["id", "org_id", "name", "enabled", "min_tls", "external_recipients", "domain_rules"]) {
      expect(p).toHaveProperty(key);
    }
    expect(p.org_id).toBe(orgId);
    expect(typeof p.name).toBe("string");
    // The internal camelCase projection must not leak onto the wire.
    expect(p).not.toHaveProperty("minTls");
    expect(p).not.toHaveProperty("domainRules");
  });

  it("maps writes on a nonexistent org to 404 not.found, not an FK 500 (ADM-T250-13)", async () => {
    const ghost = "org-00000000-0000-0000-0000-000000000000";
    // The actor must be BOUND to the ghost org — an unbound caller is denied
    // by RBAC before the existence check runs (orgId null ≠ non-null target).
    const ghostHeaders = { "x-kiwi-subject": "ghost-admin", "x-kiwi-roles": "org_admin", "x-kiwi-org": ghost };
    const user = await api(`/api/v1/orgs/${ghost}/users`, {
      method: "POST",
      body: { email: "ghost@x.test" },
      headers: ghostHeaders,
    });
    expect(user.status).toBe(404);
    expect(user.json.error.code).toBe("not.found");

    const policy = await api(`/api/v1/orgs/${ghost}/policies`, {
      method: "POST",
      body: { name: "ghost", enabled: true, min_tls: null, external_recipients: "allow", domain_rules: [] },
      headers: ghostHeaders,
    });
    expect(policy.status).toBe(404);
    expect(policy.json.error.code).toBe("not.found");
  });

  it("returns the FULL audit record, hash fields included (ADM-T250-02)", async () => {
    const q = await api(`/api/v1/audit?limit=5`, { headers: adminHeaders });
    expect(q.status).toBe(200);
    const row = (q.json.items as Record<string, unknown>[])[0]!;
    for (const key of [
      "seq", "ts", "actor_subject", "actor_roles", "org_id", "action",
      "resource", "outcome", "request_id", "details", "prev_hash", "entry_hash",
    ]) {
      expect(row).toHaveProperty(key);
    }
    expect(typeof row.entry_hash).toBe("string");
  });

  it("marks a truncated verify window with complete:false and refuses to claim valid (ADM-T250-03)", async () => {
    const partial = await api(`/api/v1/audit/verify?limit=1`, { headers: adminHeaders });
    expect(partial.status).toBe(200);
    expect(partial.json.complete).toBe(false);
    expect(partial.json.valid).toBe(false);
    const full = await api(`/api/v1/audit/verify?limit=10000`, { headers: adminHeaders });
    expect(full.json.complete).toBe(true);
    expect(full.json.valid).toBe(true);
  });

  it("audits a read denial — the refused caller leaves a denied row (ADM-T250-04)", async () => {
    const other = await api("/api/v1/orgs", { method: "POST", body: { name: "t259-deny.test" }, headers: adminHeaders });
    const otherId = (other.json as { id: string }).id;
    const denied = await api(`/api/v1/orgs/${otherId}/users`, { headers: boundHeaders });
    expect(denied.status).toBe(403);
    const rows = handle.container.db!.all(
      `SELECT action, outcome, org_id, actor_subject FROM audit_log WHERE action = 'user.list' AND outcome = 'denied'`,
    ) as { action: string; outcome: string; org_id: string | null; actor_subject: string }[];
    expect(rows.some((r) => r.org_id === otherId && r.actor_subject === "tester")).toBe(true);
  });

  it("serves the org-scoped audit export (ADM-T250-07, §13.6)", async () => {
    const r = await apiRaw(`/api/v1/orgs/${orgId}/audit/export`, boundHeaders);
    expect(r.status).toBe(200);
    expect(r.contentType).toContain("application/x-ndjson");
    const lines = r.text.split("\n").filter((l) => l.length > 0);
    const header = JSON.parse(lines[0]!) as { type: string; version: string; scope: string; org_id: string };
    expect(header.type).toBe("header");
    expect(header.version).toBe("kiwi.audit-export-org/1");
    expect(header.scope).toBe("org");
    expect(header.org_id).toBe(orgId);
    const scope = JSON.parse(lines[lines.length - 2]!) as { type: string; org_id: string; chain_claim: string };
    expect(scope.type).toBe("scope_state");
    expect(scope.org_id).toBe(orgId);
    expect(scope.chain_claim).toBe("none");
    // Every record line is this org's — the artifact can never mix orgs.
    const records = lines.slice(1, -2).map((l) => JSON.parse(l) as { org_id: string | null });
    expect(records.every((rec) => rec.org_id === orgId)).toBe(true);
    const sig = JSON.parse(lines[lines.length - 1]!) as { type: string; signed: boolean; signature: string };
    expect(sig.type).toBe("signature");
    expect(sig.signed).toBe(true);
    expect(sig.signature).toBe(
      createHmac("sha256", EXPORT_KEY).update(lines.slice(0, -1).join("\n")).digest("hex"),
    );
    // Org-scoped self-audit row, per §13.4.
    const own = await api(`/api/v1/audit?org=${orgId}&limit=1000`, { headers: boundHeaders });
    const items = own.json.items as { action: string; outcome: string; org_id: string | null }[];
    expect(items.some((i) => i.action === "audit.export" && i.outcome === "allowed" && i.org_id === orgId)).toBe(true);
  });

  it("denies the org-scoped export cross-org and to the global-only system-admin", async () => {
    const other = await api("/api/v1/orgs", { method: "POST", body: { name: "t259-exp-b.test" }, headers: adminHeaders });
    const otherId = (other.json as { id: string }).id;
    // Org-bound admin aimed at a foreign org.
    const cross = await apiRaw(`/api/v1/orgs/${otherId}/audit/export`, boundHeaders);
    expect(cross.status).toBe(403);
    // The platform role on the org route — its surface is the global route.
    const sys = await apiRaw(`/api/v1/orgs/${orgId}/audit/export`, systemAdminHeaders);
    expect(sys.status).toBe(403);
    // The cross-org denial is audited with the target org's id.
    const rows = handle.container.db!.all(
      `SELECT action, outcome, org_id FROM audit_log WHERE action = 'audit.export' AND outcome = 'denied'`,
    ) as { action: string; outcome: string; org_id: string | null }[];
    expect(rows.some((r) => r.org_id === otherId)).toBe(true);
  });

  it("rejects granting the platform-only system-admin role into an org (T-259)", async () => {
    // GRANTABLE_ORG_ROLES excludes it — a grant would fail the table CHECK.
    const u = await api(`/api/v1/orgs/${orgId}/users`, {
      method: "POST",
      body: { email: "grant-target@http.test" },
      headers: boundHeaders,
    });
    const uid = (u.json as { id: string }).id;
    const grant = await api(`/api/v1/orgs/${orgId}/users/${uid}/role`, {
      method: "PUT",
      body: { role: "system-admin" },
      headers: boundHeaders,
    });
    expect(grant.status).toBe(400);
    expect(grant.json.error.code).toBe("validation.failed");
  });
});
