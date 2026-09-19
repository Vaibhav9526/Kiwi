/** Localhost HTTP transport tests (T-134): contract wire mapping over services. */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startServer, type ServerHandle } from "../src/server.js";
import { makeTempDbPath } from "./helpers/db.js";

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

const adminHeaders = { "x-kiwi-subject": "tester", "x-kiwi-roles": "org_admin" };
const viewerHeaders = { "x-kiwi-subject": "viewer", "x-kiwi-roles": "viewer", "x-kiwi-org": "__ORG__" };

let orgId = "";

beforeAll(async () => {
  handle = await startServer({ dbPath: makeTempDbPath(), port: 0 });
  base = `http://127.0.0.1:${handle.port}`;
  const created = await api("/api/v1/orgs", { method: "POST", body: { name: "http.test" }, headers: adminHeaders });
  expect(created.status).toBe(201);
  orgId = (created.json as { id: string }).id as string;
  viewerHeaders["x-kiwi-org"] = orgId;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => handle.server.close((e) => (e ? reject(e) : resolve())));
  handle.container.close();
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
      headers: adminHeaders,
    });
    expect(created.status).toBe(201);
    const userId = (created.json as { id: string }).id as string;

    const granted = await api(`/api/v1/orgs/${orgId}/users/${userId}/role`, {
      method: "PUT",
      body: { role: "viewer" },
      headers: adminHeaders,
    });
    expect(granted.status).toBe(200);

    const listed = await api(`/api/v1/orgs/${orgId}/users`, { headers: adminHeaders });
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
      headers: adminHeaders,
    });
    expect(created.status).toBe(201);
    const policyId = (created.json as { id: string }).id as string;

    const listed = await api(`/api/v1/orgs/${orgId}/policies`, { headers: adminHeaders });
    expect(listed.status).toBe(200);
    expect((listed.json.items as { id: string }[]).some((p) => p.id === policyId)).toBe(true);

    const single = await api(`/api/v1/policies/${policyId}/evaluate`, {
      method: "POST",
      body: { direction: "outbound", sender: "a@http.test", recipient: "b@partner.example", tlsVersion: "tls1.3" },
      headers: adminHeaders,
    });
    expect(single.json.verdict).toBe("allow");

    const bridge = await api(`/api/v1/orgs/${orgId}/policies/evaluate-outbound`, {
      method: "POST",
      body: { sender: "a@http.test", recipients: ["b@partner.example", "c@stranger.test"], tlsVersion: "tls1.0" },
      headers: adminHeaders,
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
      headers: adminHeaders,
    });
    expect(ingested.status).toBe(201);

    const queried = await api(`/api/v1/mailflow/events?org=${orgId}&limit=10`, { headers: adminHeaders });
    expect(queried.status).toBe(200);
    expect((queried.json.items as { recipient: string }[]).some((e) => e.recipient === "b@partner.example")).toBe(true);
  });

  it("reads and verifies the audit log", async () => {
    const q = await api(`/api/v1/audit?limit=5`, { headers: adminHeaders });
    expect(q.status).toBe(200);
    expect(Array.isArray(q.json.items)).toBe(true);
    const v = await api(`/api/v1/audit/verify?limit=1000`, { headers: adminHeaders });
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
      headers: adminHeaders,
    });
    expect(bad.status).toBe(400);
    expect(bad.json.error.code).toBe("validation.failed");

    const missing = await api("/api/v1/nope", { headers: adminHeaders });
    expect(missing.status).toBe(404);
    expect(missing.json.error.code).toBe("not.found");
  });
});
