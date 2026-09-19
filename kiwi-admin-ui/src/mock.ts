/**
 * Demo backend (T-134). Used when the kiwi-admin service is unreachable —
 * every view badges this mode. Enforces the contract §2 permission matrix
 * locally so the role switcher demonstrates real allow/deny paths. Bridge
 * verdicts are trivially derived and labeled DEMO (never confuse with the
 * deterministic server evaluator).
 */
import type {
  ActorRole,
  AdminApi,
  AuditRow,
  DomainRule,
  MailflowEvent,
  Org,
  OrgUser,
  OutboundEvaluation,
  PolicyObject,
} from "./api";
import { ApiError } from "./api";

const ROLE_PERMS: Record<ActorRole, Set<string>> = {
  org_admin: new Set([
    "org.read", "org.create", "user.read", "user.invite", "user.role.grant", "device.revoke",
    "policy.read", "policy.write", "mailflow.read", "mailflow.ingest", "audit.read",
  ]),
  security_admin: new Set([
    "org.read", "user.read", "device.revoke", "policy.read", "policy.write", "mailflow.read", "audit.read",
  ]),
  viewer: new Set(["org.read", "user.read", "policy.read", "mailflow.read", "audit.read"]),
};

let seq = 0;
const nid = (p: string): string => `${p}-demo-${++seq}`;

export class MockAdminApi implements AdminApi {
  readonly mode = "demo" as const;
  private orgs: Org[] = [{ id: "org-demo", name: "demo.test", created_at: 1000 }];
  private users: OrgUser[] = [
    { id: "user-demo-1", email: "admin@demo.test", roles: ["org_admin"], created_at: 1010 },
    { id: "user-demo-2", email: "soc@demo.test", roles: ["security_admin"], created_at: 1020 },
  ];
  private policies: (PolicyObject & { org_id: string })[] = [
    {
      id: "pol-demo", org_id: "org-demo", name: "default-outbound", enabled: true,
      min_tls: "tls1.2", external_recipients: "warn",
      domain_rules: [{ domain: "partner.example", action: "allow" }],
    },
  ];
  private mailflow: MailflowEvent[] = [
    {
      id: "evt-demo-1", org_id: "org-demo", direction: "outbound", sender: "a@demo.test",
      recipient: "b@partner.example", ts: 2000, message_id: null, tls_version: "tls1.3",
      security_status: "clean", policy_verdict: "allow", received_at: 2001,
    },
  ];
  private audit: AuditRow[] = [
    { seq: 1, ts: 1000, actor_subject: "admin@demo.test", action: "org.create", outcome: "allowed", details: "{}" },
  ];

  constructor(private readonly role: ActorRole) {}

  private require(perm: string): void {
    if (!ROLE_PERMS[this.role].has(perm)) {
      throw new ApiError(403, "auth.denied", `demo role '${this.role}' lacks permission '${perm}'`);
    }
  }

  private log(action: string, outcome: string): void {
    this.audit.push({
      seq: this.audit.length + 1, ts: 3000 + this.audit.length,
      actor_subject: `demo-${this.role}`, action, outcome, details: "{}",
    });
  }

  async health(): Promise<{ status: string; contract: string }> {
    return { status: "ok (demo)", contract: "admin-api/1.3" };
  }

  async createOrg(name: string): Promise<Org> {
    this.require("org.create");
    const org = { id: nid("org"), name, created_at: 3000 };
    this.orgs.push(org);
    this.log("org.create", "allowed");
    return org;
  }

  async listUsers(orgId: string): Promise<OrgUser[]> {
    this.require("user.read");
    void orgId;
    return this.users;
  }

  async createUser(orgId: string, email: string): Promise<{ id: string }> {
    this.require("user.invite");
    void orgId;
    if (!email.includes("@")) throw new ApiError(400, "validation.failed", "invalid email: expected string with @");
    const id = nid("user");
    this.users.push({ id, email, roles: [], created_at: 3000 });
    this.log("user.create", "allowed");
    return { id };
  }

  async grantRole(orgId: string, userId: string, role: ActorRole): Promise<void> {
    this.require("user.role.grant");
    void orgId;
    const u = this.users.find((x) => x.id === userId);
    if (!u) throw new ApiError(404, "not.found", `user '${userId}' not found`);
    u.roles = [role];
    this.log("user.role.grant", "allowed");
  }

  async revokeDevice(deviceId: string): Promise<void> {
    this.require("device.revoke");
    void deviceId;
    this.log("device.revoke", "allowed");
  }

  async listPolicies(orgId: string): Promise<PolicyObject[]> {
    this.require("policy.read");
    return this.policies.filter((p) => p.org_id === orgId);
  }

  async createPolicy(
    orgId: string,
    input: { name: string; enabled: boolean; min_tls: string | null; external_recipients: "allow" | "warn" | "block"; domain_rules: DomainRule[] },
  ): Promise<{ id: string }> {
    this.require("policy.write");
    const id = nid("pol");
    this.policies.push({ id, org_id: orgId, ...input });
    this.log("policy.create", "allowed");
    return { id };
  }

  /** DEMO verdicts only — trivial local rules, not the server evaluator. */
  async evaluateOutbound(
    orgId: string,
    input: { sender: string; recipients: string[]; tlsVersion: string | null },
  ): Promise<OutboundEvaluation> {
    this.require("policy.read");
    void orgId;
    void input.sender;
    const results = input.recipients.map((r) => {
      const dom = r.split("@")[1]?.toLowerCase() ?? "";
      if (r.endsWith("@blocked.test")) {
        return { recipient: r, verdict: "block" as const, reasons: [{ code: "recipient-domain-blocked (demo)", detail: dom }], policyId: "pol-demo" };
      }
      if (!dom.endsWith(".test")) {
        return { recipient: r, verdict: "warn" as const, reasons: [{ code: "external-recipient (demo)", detail: dom }], policyId: "pol-demo" };
      }
      return { recipient: r, verdict: "allow" as const, reasons: [{ code: "recipient-domain-allowed (demo)", detail: dom }], policyId: "pol-demo" };
    });
    const overall = results.some((x) => x.verdict === "block") ? "block" : results.some((x) => x.verdict === "warn") ? "warn" : "allow";
    return { orgId, overall, results };
  }

  async ingestMailflow(ev: {
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
    this.require("mailflow.ingest");
    const id = nid("evt");
    this.mailflow.unshift({ id, ...ev, received_at: 3000 });
    this.log("mailflow.ingest", "allowed");
    return { id };
  }

  async queryMailflow(params: { org?: string; recipientDomain?: string; limit: number }): Promise<MailflowEvent[]> {
    this.require("mailflow.read");
    return this.mailflow
      .filter((e) => (!params.org || e.org_id === params.org) && (!params.recipientDomain || e.recipient.endsWith(`@${params.recipientDomain}`)))
      .slice(0, Math.min(params.limit, 1000));
  }

  async queryAudit(params: { limit: number }): Promise<AuditRow[]> {
    this.require("audit.read");
    return this.audit.slice(-Math.min(params.limit, 1000)).reverse();
  }

  async verifyAudit(_limit: number): Promise<{ valid: boolean; checked: number; error: string | null }> {
    this.require("audit.read");
    return { valid: true, checked: this.audit.length, error: null };
  }
}
