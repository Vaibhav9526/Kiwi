/**
 * Typed admin API client (T-134) — shapes follow docs/contracts/admin-api.md
 * v1.3 wire mapping. No business logic: transport + error normalization only.
 * RBAC verdicts come from the server; the UI only renders them.
 */

export interface Org {
  id: string;
  name: string;
  created_at: number;
}

export interface OrgUser {
  id: string;
  email: string;
  roles: string[];
  created_at: number;
}

export interface DomainRule {
  domain: string;
  action: "allow" | "block";
}

export interface PolicyObject {
  id: string;
  name?: string;
  enabled: boolean;
  min_tls: string | null;
  external_recipients: "allow" | "warn" | "block";
  domain_rules: DomainRule[];
}

export interface PolicyReason {
  code: string;
  detail?: string;
}

export interface RecipientResult {
  recipient: string;
  verdict: "allow" | "warn" | "block";
  reasons: PolicyReason[];
  policyId: string | null;
}

export interface OutboundEvaluation {
  orgId: string;
  overall: "allow" | "warn" | "block";
  results: RecipientResult[];
}

export interface MailflowEvent {
  id: string;
  org_id: string | null;
  direction: "inbound" | "outbound";
  sender: string;
  recipient: string;
  ts: number;
  message_id: string | null;
  tls_version: string | null;
  security_status: string;
  policy_verdict: string;
  received_at: number;
}

export interface AuditRow {
  seq: number;
  ts: number;
  actor_subject: string | null;
  action: string;
  outcome: string;
  details: string | null;
}

export type ActorRole = "org_admin" | "security_admin" | "viewer";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Full admin surface used by the views (mirrors the §3 + §10 endpoint table). */
export interface AdminApi {
  readonly mode: "live" | "demo";
  health(): Promise<{ status: string; contract: string }>;
  createOrg(name: string): Promise<Org>;
  listUsers(orgId: string): Promise<OrgUser[]>;
  createUser(orgId: string, email: string): Promise<{ id: string }>;
  grantRole(orgId: string, userId: string, role: ActorRole): Promise<void>;
  revokeDevice(deviceId: string): Promise<void>;
  listPolicies(orgId: string): Promise<PolicyObject[]>;
  createPolicy(
    orgId: string,
    input: { name: string; enabled: boolean; min_tls: string | null; external_recipients: "allow" | "warn" | "block"; domain_rules: DomainRule[] },
  ): Promise<{ id: string }>;
  evaluateOutbound(
    orgId: string,
    input: { sender: string; recipients: string[]; tlsVersion: string | null },
  ): Promise<OutboundEvaluation>;
  ingestMailflow(ev: {
    direction: "inbound" | "outbound";
    sender: string;
    recipient: string;
    ts: number;
    message_id: string | null;
    tls_version: string | null;
    security_status: string;
    policy_verdict: string;
    org_id: string | null;
  }): Promise<{ id: string }>;
  queryMailflow(params: { org?: string; recipientDomain?: string; limit: number }): Promise<MailflowEvent[]>;
  queryAudit(params: { limit: number }): Promise<AuditRow[]>;
  verifyAudit(limit: number): Promise<{ valid: boolean; checked: number; error: string | null }>;
}

export class HttpAdminApi implements AdminApi {
  readonly mode = "live" as const;
  constructor(
    private readonly baseUrl: string,
    private readonly actor: { subject: string; roles: ActorRole[]; orgId: string | null },
  ) {}

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      "content-type": "application/json",
      "x-kiwi-subject": this.actor.subject,
      "x-kiwi-roles": this.actor.roles.join(","),
    };
    if (this.actor.orgId) h["x-kiwi-org"] = this.actor.orgId;
    return h;
  }

  private async call<T>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${path}`, {
        method: opts.method ?? "GET",
        headers: this.headers(),
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      });
    } catch (e) {
      throw new ApiError(0, "transport.failed", `backend unreachable at ${this.baseUrl}: ${e instanceof Error ? e.message : e}`);
    }
    const json = (await res.json()) as { error?: { code: string; message: string }; items?: T; [k: string]: unknown };
    if (!res.ok) {
      throw new ApiError(res.status, json.error?.code ?? "unknown", json.error?.message ?? `HTTP ${res.status}`);
    }
    if (Array.isArray(json.items)) return json.items as T;
    return json as T;
  }

  health(): Promise<{ status: string; contract: string }> {
    return this.call("/healthz");
  }
  createOrg(name: string): Promise<Org> {
    return this.call("/api/v1/orgs", { method: "POST", body: { name } });
  }
  listUsers(orgId: string): Promise<OrgUser[]> {
    return this.call(`/api/v1/orgs/${encodeURIComponent(orgId)}/users`);
  }
  createUser(orgId: string, email: string): Promise<{ id: string }> {
    return this.call(`/api/v1/orgs/${encodeURIComponent(orgId)}/users`, { method: "POST", body: { email } });
  }
  async grantRole(orgId: string, userId: string, role: ActorRole): Promise<void> {
    await this.call(`/api/v1/orgs/${encodeURIComponent(orgId)}/users/${encodeURIComponent(userId)}/role`, {
      method: "PUT",
      body: { role },
    });
  }
  async revokeDevice(deviceId: string): Promise<void> {
    await this.call(`/api/v1/devices/${encodeURIComponent(deviceId)}/revoke`, { method: "POST" });
  }
  listPolicies(orgId: string): Promise<PolicyObject[]> {
    return this.call(`/api/v1/orgs/${encodeURIComponent(orgId)}/policies`);
  }
  createPolicy(
    orgId: string,
    input: { name: string; enabled: boolean; min_tls: string | null; external_recipients: "allow" | "warn" | "block"; domain_rules: DomainRule[] },
  ): Promise<{ id: string }> {
    return this.call(`/api/v1/orgs/${encodeURIComponent(orgId)}/policies`, { method: "POST", body: input });
  }
  evaluateOutbound(
    orgId: string,
    input: { sender: string; recipients: string[]; tlsVersion: string | null },
  ): Promise<OutboundEvaluation> {
    return this.call(`/api/v1/orgs/${encodeURIComponent(orgId)}/policies/evaluate-outbound`, { method: "POST", body: input });
  }
  ingestMailflow(ev: {
    direction: "inbound" | "outbound";
    sender: string;
    recipient: string;
    ts: number;
    message_id: string | null;
    tls_version: string | null;
    security_status: string;
    policy_verdict: string;
    org_id: string | null;
  }): Promise<{ id: string }> {
    return this.call("/api/v1/mailflow/events", { method: "POST", body: ev });
  }
  queryMailflow(params: { org?: string; recipientDomain?: string; limit: number }): Promise<MailflowEvent[]> {
    const q = new URLSearchParams({ limit: String(params.limit) });
    if (params.org) q.set("org", params.org);
    if (params.recipientDomain) q.set("recipientDomain", params.recipientDomain);
    return this.call(`/api/v1/mailflow/events?${q.toString()}`);
  }
  queryAudit(params: { limit: number }): Promise<AuditRow[]> {
    return this.call(`/api/v1/audit?limit=${params.limit}`);
  }
  verifyAudit(limit: number): Promise<{ valid: boolean; checked: number; error: string | null }> {
    return this.call(`/api/v1/audit/verify?limit=${limit}`);
  }
}
