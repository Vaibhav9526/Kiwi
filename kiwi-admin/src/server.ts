/**
 * Minimal localhost HTTP transport over the kiwi-admin services (T-134).
 * Implements the wire mapping in docs/contracts/admin-api.md §3 (+§10 bridge)
 * plus GET /healthz for process supervision (Agent 6 T-133).
 *
 * DEV-SCAFFOLD AUTH WARNING: actor identity comes from `x-kiwi-*` request
 * headers (see actorFromHeaders). That is LOCAL-DEV-ONLY scaffolding — the
 * service binds 127.0.0.1 and refuses any other interface. Real session auth
 * (kiwi-core identity, Phase 3+) replaces header actors before this transport
 * is used for anything beyond local development. Never expose this port.
 *
 * Zero dependencies beyond node stdlib. All business rules stay in services;
 * this layer only parses HTTP, validates boundary shapes, and maps errors to
 * the contract's uniform error shape.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { createServiceContainer, type ServiceContainer } from "./services.js";
import { AuthorizationDeniedError, type Actor } from "./rbac/rbac.js";
import { ConflictError, NotFoundError, RequestValidationError, isRecord } from "./util/validate.js";
import { ALL_ORG_ROLES, TLS_VERSION_ALIASES, type ExternalRecipientBehavior, type OrgRole } from "./types.js";
import { AUDIT_EXPORT_CONTENT_TYPE } from "./audit/export.js";

const HOST = "127.0.0.1";
const DEFAULT_PORT = 8471;
const MAX_BODY_BYTES = 1024 * 1024;

/**
 * Audit-export signing key (T-179). Read once at startup from the environment.
 * Callers may override it per server (tests pin it; compose supplies it), which
 * keeps this out of the request path and makes the export deterministic under
 * test. The key is NEVER logged and never echoed — the export carries only its
 * SHA-256 fingerprint (audit/export.ts). Absent means exports are unsigned, and
 * the export says so rather than emitting a placeholder signature.
 */
const EXPORT_KEY_FROM_ENV = (process.env["KIWI_AUDIT_EXPORT_KEY"] ?? "").trim() || null;

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(payload) });
  res.end(payload);
}

/**
 * NDJSON is written as a raw body — `send()` would JSON-encode the newlines and
 * destroy the line structure. `no-store` because the audit log is evidence:
 * a cached or intermediary-transformed copy is worse than no copy.
 */
function sendNdjson(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, {
    "content-type": `${AUDIT_EXPORT_CONTENT_TYPE}; charset=utf-8`,
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  res.end(body);
}

function errBody(code: string, message: string, details?: Record<string, unknown>): unknown {
  return details === undefined ? { error: { code, message } } : { error: { code, message, details } };
}

/**
 * DEV-SCAFFOLD AUTH: the actor is taken from request headers. This is
 * LOCAL-DEV-ONLY scaffolding, NOT authentication — a caller can claim any
 * subject and any role. The service binds 127.0.0.1 and refuses any other
 * interface, and real session auth (kiwi-core identity, Phase 3+) replaces
 * this before the port is exposed to anything. See admin-api.md §3.2.
 *
 * The role set IS fail-closed, though: an absent or unparseable `x-kiwi-roles`
 * yields NO roles rather than a default admin. A request that forgets the
 * header is unauthenticated, so it must be refused — silently promoting it to
 * org_admin (the previous behaviour) turned a typo into full privilege. The
 * subject keeps a placeholder only so the resulting denial is attributable.
 */
function actorFromHeaders(req: IncomingMessage): Actor {
  const get = (name: string): string | undefined => {
    const v = req.headers[name];
    return typeof v === "string" ? v : undefined;
  };
  const subject = get("x-kiwi-subject")?.trim() || "local-unauthenticated";
  const roles = (get("x-kiwi-roles") ?? "")
    .split(",")
    .map((r) => r.trim())
    .filter((r): r is OrgRole => (ALL_ORG_ROLES as readonly string[]).includes(r));
  const orgId = get("x-kiwi-org")?.trim() || null;
  return { subject, roles, orgId };
}

function readJson(req: IncomingMessage): Promise<unknown> {
  // Content-type gate (T-193/L3): bodies are JSON, full stop. A form-encoded
  // or text body that happens to parse is not an API call — say so plainly
  // instead of guessing the caller's intent.
  const contentType = req.headers["content-type"];
  if (typeof contentType !== "string" || !contentType.split(";")[0]?.trim().toLowerCase().includes("application/json")) {
    throw new RequestValidationError("content-type", "expected application/json");
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new RequestValidationError("body", "exceeds 1 MiB"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8").trim();
      if (!text) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(text) as unknown);
      } catch {
        reject(new RequestValidationError("body", "malformed JSON"));
      }
    });
    req.on("error", reject);
  });
}

function strField(body: Record<string, unknown>, field: string, max = 4096): string {
  const v = body[field];
  if (typeof v !== "string" || v.trim().length === 0) throw new RequestValidationError(field, "expected non-empty string");
  if (v.trim().length > max) throw new RequestValidationError(field, `exceeds ${max} chars`);
  return v.trim();
}

/** Wire shape per contract §5.1 (snake_case PolicyObject minus id). */
function parsePolicyBody(body: unknown): {
  name: string;
  enabled: boolean;
  minTls: string | null;
  externalRecipients: ExternalRecipientBehavior;
  domainRules: { domain: string; action: "allow" | "block" }[];
} {
  if (!isRecord(body)) throw new RequestValidationError("body", "expected object");
  const name = strField(body, "name", 200);
  if (typeof body["enabled"] !== "boolean") throw new RequestValidationError("enabled", "expected boolean");
  const ext = body["external_recipients"];
  if (ext !== "allow" && ext !== "warn" && ext !== "block") {
    throw new RequestValidationError("external_recipients", "must be allow|warn|block");
  }
  let minTls: string | null = null;
  const rawTls = body["min_tls"];
  if (rawTls !== undefined && rawTls !== null) {
    if (typeof rawTls !== "string") throw new RequestValidationError("min_tls", "expected string");
    const normalized = TLS_VERSION_ALIASES[rawTls.trim().toLowerCase()];
    if (!normalized) throw new RequestValidationError("min_tls", "unrecognized TLS version");
    minTls = normalized;
  }
  const rulesRaw = body["domain_rules"] ?? [];
  if (!Array.isArray(rulesRaw)) throw new RequestValidationError("domain_rules", "expected array");
  const domainRules = rulesRaw.map((r) => {
    if (!isRecord(r)) throw new RequestValidationError("domain_rules[]", "expected object");
    const domain = strField(r, "domain", 253);
    const actionRaw = r["action"];
    if (actionRaw !== "allow" && actionRaw !== "block") {
      throw new RequestValidationError("domain_rules[].action", "must be allow|block");
    }
    const action: "allow" | "block" = actionRaw;
    return { domain, action };
  });
  return { name, enabled: body["enabled"], minTls, externalRecipients: ext, domainRules };
}

function numParam(url: URL, name: string, fallback: number): number {
  const raw = url.searchParams.get(name);
  if (raw === null) return fallback;
  // Strict decimal grammar (T-193/L2): `Number()` coerces hex, exponents
  // and whitespace (`0x10`, `1e3`, `" 12"`). The wire contract is decimal
  // digits with an optional leading minus — nothing else.
  if (!/^-?\d+$/.test(raw)) throw new RequestValidationError(name, "expected decimal integer");
  const n = Number(raw);
  if (!Number.isSafeInteger(n)) throw new RequestValidationError(name, "expected integer");
  return n;
}

export interface HttpServerOptions {
  /**
   * Overrides the export signing key. `undefined` follows the environment;
   * `null` forces unsigned. `| undefined` is explicit because callers forward
   * their own optional parameter (see ServiceContainerOptions).
   */
  auditExportKey?: string | null | undefined;
}

export function createHttpServer(container: ServiceContainer, opts: HttpServerOptions = {}): Server {
  const exportKey =
    opts.auditExportKey === undefined ? EXPORT_KEY_FROM_ENV : (opts.auditExportKey ?? "").trim() || null;
  return createServer(async (req, res) => {
    try {
      await route(container, req, res, exportKey);
    } catch (err) {
      if (err instanceof AuthorizationDeniedError) {
        send(res, 403, errBody("auth.denied", err.message, { permission: err.permission }));
      } else if (err instanceof RequestValidationError) {
        send(res, 400, errBody("validation.failed", err.message));
      } else if (err instanceof NotFoundError) {
        send(res, 404, errBody("not.found", err.message));
      } else if (err instanceof ConflictError) {
        send(res, 409, errBody("conflict", err.message));
      } else {
        // Generic 500 (T-193/M4): the full error goes to the server log with
        // a correlation id; the wire carries nothing internal — no driver
        // constraint names, no relation names, no DSN fragments. Typed
        // errors above are the only path to a specific message.
        // eslint-disable-next-line no-console
        const ref = randomUUID().slice(0, 8);
        console.error(`[kiwi-admin] request failed ref=${ref}`, err);
        send(res, 500, errBody("internal", `unexpected error (ref ${ref})`));
      }
    }
  });
}

async function route(
  container: ServiceContainer,
  req: IncomingMessage,
  res: ServerResponse,
  exportKey: string | null,
): Promise<void> {
  const url = new URL(req.url ?? "/", `http://${HOST}`);
  const method = (req.method ?? "GET").toUpperCase();
  const seg = url.pathname.split("/").filter((s) => s.length > 0);
  const actor = actorFromHeaders(req);
  const now = Math.floor(Date.now() / 1000);

  if (method === "GET" && seg.length === 1 && seg[0] === "healthz") {
    send(res, 200, { status: "ok", service: "kiwi-admin", version: "0.1.0", contract: "admin-api/1.3" });
    return;
  }

  if (seg[0] !== "api" || seg[1] !== "v1") {
    send(res, 404, errBody("not.found", `no route ${method} ${url.pathname}`));
    return;
  }
  const rest = seg.slice(2);

  // POST /api/v1/orgs
  if (method === "POST" && rest.length === 1 && rest[0] === "orgs") {
    const body = (await readJson(req)) as Record<string, unknown>;
    send(res, 201, await container.orgs.createOrg(actor, strField(body, "name", 200), now));
    return;
  }

  // /api/v1/orgs/:org/...
  if (rest[0] === "orgs" && typeof rest[1] === "string") {
    const orgId = rest[1];
    // POST /users | GET /users
    if (rest[2] === "users" && rest.length === 3) {
      if (method === "POST") {
        const body = (await readJson(req)) as Record<string, unknown>;
        send(res, 201, await container.orgs.createUser(actor, orgId, strField(body, "email", 254), now));
        return;
      }
      if (method === "GET") {
        // Bounded listing (T-193/M7): default 50, hard cap 500.
        send(res, 200, { items: await container.orgs.listUsers(actor, orgId, numParam(url, "limit", 50)) });
        return;
      }
    }
    // PUT /users/:user/role
    if (rest[2] === "users" && typeof rest[3] === "string" && rest[4] === "role" && rest.length === 5 && method === "PUT") {
      const body = (await readJson(req)) as Record<string, unknown>;
      const role = body["role"];
      if (role !== "org_admin" && role !== "security_admin" && role !== "viewer") {
        throw new RequestValidationError("role", "must be org_admin|security_admin|viewer");
      }
      await container.orgs.grantRole(actor, rest[3], orgId, role, now);
      send(res, 200, { ok: true });
      return;
    }
    // GET|POST /policies
    if (rest[2] === "policies" && rest.length === 3) {
      if (method === "GET") {
        // Bounded listing (T-193/M7): default 50, hard cap 500.
        send(res, 200, { items: await container.policies.listPolicies(actor, orgId, numParam(url, "limit", 50)) });
        return;
      }
      if (method === "POST") {
        const input = parsePolicyBody(await readJson(req));
        send(
          res,
          201,
          await container.policies.createPolicy(actor, orgId, input.name, {
            name: input.name,
            enabled: input.enabled,
            minTls: input.minTls,
            externalRecipients: input.externalRecipients,
            domainRules: input.domainRules,
          }),
        );
        return;
      }
    }
    // POST /policies/evaluate-outbound
    if (rest[2] === "policies" && rest[3] === "evaluate-outbound" && rest.length === 4 && method === "POST") {
      const body = (await readJson(req)) as Record<string, unknown>;
      send(
        res,
        200,
        await container.policies.evaluateOutbound(actor, orgId, {
          sender: body["sender"],
          recipients: body["recipients"],
          tlsVersion: body["tlsVersion"] ?? body["tls_version"] ?? null,
        }),
      );
      return;
    }
  }

  // POST /api/v1/devices/:device/revoke
  if (method === "POST" && rest[0] === "devices" && typeof rest[1] === "string" && rest[2] === "revoke" && rest.length === 3) {
    await container.orgs.revokeDevice(actor, rest[1], now);
    send(res, 200, { ok: true });
    return;
  }

    // POST /api/v1/policies/:policy/evaluate
    if (method === "POST" && rest[0] === "policies" && typeof rest[1] === "string" && rest[2] === "evaluate" && rest.length === 3) {
      const body = (await readJson(req)) as Record<string, unknown>;
      const direction = body["direction"];
      if (direction !== "inbound" && direction !== "outbound") throw new RequestValidationError("direction", "must be inbound|outbound");
      const tlsRaw = body["tlsVersion"] ?? body["tls_version"] ?? null;
      let tlsVersion: string | null = null;
      if (tlsRaw !== null) {
        if (typeof tlsRaw !== "string") throw new RequestValidationError("tlsVersion", "expected string");
        const normalized = TLS_VERSION_ALIASES[tlsRaw.trim().toLowerCase()];
        if (!normalized) throw new RequestValidationError("tlsVersion", "unrecognized TLS version");
        tlsVersion = normalized;
      }
      // Authenticated evaluation (T-193/H1): the actor travels with the
      // call so the service can check `policy.read` on the owning org and
      // audit the outcome. Previously the identity was parsed and dropped.
      send(
        res,
        200,
        await container.policies.evaluate(actor, rest[1], {
          direction,
          sender: strField(body, "sender", 254),
          recipient: strField(body, "recipient", 254),
          tlsVersion,
        }),
      );
      return;
    }

  // POST|GET /api/v1/mailflow/events
  if (rest[0] === "mailflow" && rest[1] === "events" && rest.length === 2) {
    if (method === "POST") {
      const body = (await readJson(req)) as Record<string, unknown>;
      send(
        res,
        201,
        await container.mailflow.ingest(actor, {
          direction: body["direction"] as "inbound" | "outbound",
          sender: body["sender"] as string,
          recipient: body["recipient"] as string,
          ts: body["ts"] as number,
          message_id: (body["message_id"] as string | null | undefined) ?? null,
          tls_version: (body["tls_version"] as string | null | undefined) ?? null,
          security_status: (body["security_status"] as string | undefined) ?? "unknown",
          policy_verdict: (body["policy_verdict"] as "allow" | "warn" | "block" | "unknown" | undefined) ?? "unknown",
          org_id: (body["org_id"] as string | null | undefined) ?? null,
        }),
      );
      return;
    }
    if (method === "GET") {
      const filter: { orgId?: string; recipientDomain?: string; sinceTs?: number; untilTs?: number; limit: number } = {
        limit: numParam(url, "limit", 50),
      };
      const org = url.searchParams.get("org");
      if (org !== null) filter.orgId = org;
      const rd = url.searchParams.get("recipientDomain");
      if (rd !== null) filter.recipientDomain = rd;
      if (url.searchParams.has("since")) filter.sinceTs = numParam(url, "since", 0);
      if (url.searchParams.has("until")) filter.untilTs = numParam(url, "until", Number.MAX_SAFE_INTEGER);
      send(res, 200, await container.mailflow.query(actor, filter));
      return;
    }
  }

  // GET /api/v1/audit | GET /api/v1/audit/verify | GET /api/v1/audit/export
  // The audit log is a security control: reading it, and reading whether its
  // chain is intact, are permissions — not givens. All three are enforced in
  // AuditService, where a denial is also attributed to the actor.
  if (rest[0] === "audit" && rest.length <= 2 && method === "GET") {
    if (rest[1] === "verify") {
      send(res, 200, await container.audit.verify(actor, { limit: numParam(url, "limit", 1000) }));
      return;
    }
    // T-179: signed NDJSON of the whole chain. `audit.export` — org_admin only.
    // No `?org=`: an export is only worth signing if it covers every row, so a
    // filtered one is refused by omission rather than silently weakened.
    if (rest[1] === "export") {
      const exported = await container.audit.export(actor, { now, key: exportKey });
      sendNdjson(res, 200, exported.ndjson);
      return;
    }
    if (rest.length === 1) {
      const filter: { orgId?: string; since?: number; until?: number; limit: number } = {
        limit: numParam(url, "limit", 50),
      };
      const org = url.searchParams.get("org");
      if (org !== null) filter.orgId = org;
      if (url.searchParams.has("since")) filter.since = numParam(url, "since", 0);
      if (url.searchParams.has("until")) filter.until = numParam(url, "until", Number.MAX_SAFE_INTEGER);
      send(res, 200, { items: await container.audit.query(actor, filter) });
      return;
    }
  }

  send(res, 404, errBody("not.found", `no route ${method} ${url.pathname}`));
}

export interface ServerHandle {
  server: Server;
  port: number;
  container: ServiceContainer;
}

/** Starts the localhost-only server. Never binds anything but 127.0.0.1. */
export async function startServer(
  opts: {
    // `| undefined` is required on the forwarded options, not decorative: this
    // function passes them straight through to `createServiceContainer` /
    // `createHttpServer` and `exactOptionalPropertyTypes` distinguishes absent
    // from explicitly undefined. See `ServiceContainerOptions`.
    dbPath?: string | undefined;
    databaseUrl?: string | null | undefined;
    /** Export signing key override; `undefined` follows the environment. */
    auditExportKey?: string | null | undefined;
    port?: number;
    container?: ServiceContainer;
  } = {},
): Promise<ServerHandle> {
  const container =
    opts.container ?? (await createServiceContainer({ dbPath: opts.dbPath, databaseUrl: opts.databaseUrl }));
  const server = createHttpServer(container, { auditExportKey: opts.auditExportKey });
  const port = opts.port ?? Number(process.env["KIWI_ADMIN_PORT"] ?? DEFAULT_PORT);
  await new Promise<void>((resolve) => server.listen(port, HOST, resolve));
  const address = server.address();
  const bound = typeof address === "object" && address ? address.port : port;
  return { server, port: bound, container };
}

const isMain = typeof process.argv[1] === "string" && import.meta.url.endsWith("/server.js") && process.argv[1].replace(/\\/g, "/").endsWith("/server.js");

if (isMain) {
  const dbPath = process.env["KIWI_ADMIN_DB"] ?? "kiwi-admin.db";
  // eslint-disable-next-line no-console
  console.warn("[kiwi-admin] DEV-SCAFFOLD transport: localhost-only, header actors — NOT production auth.");
  startServer({ dbPath })
    .then(({ port, container }) => {
      // eslint-disable-next-line no-console
      console.log(
        `[kiwi-admin] listening on http://${HOST}:${port} (${container.dialect}` +
          `${container.dialect === "sqlite" ? ` db ${dbPath}` : ""})`,
      );
    })
    .catch((err: unknown) => {
      // eslint-disable-next-line no-console
      console.error("[kiwi-admin] failed to start", err);
      process.exit(1);
    });
}
