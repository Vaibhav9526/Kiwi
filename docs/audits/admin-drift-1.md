# Admin API Drift Audit 1 (T-250)

**Reviewer:** Agent 22 · **Date:** 2026-09-25 · **Mode:** read-only analysis.
**Scope:** every method/path in `docs/contracts/admin-api.md` §3, including
`GET /healthz`, the T-188 device-inventory surface in §14, the T-179/T-188
audit-export surfaces in §13, and the current `kiwi-admin/src/` route/service/
repository implementation. No source or contract files were changed.

## Method and severity

The contract endpoint table and §§12–14 were read against `server.ts`, the
RBAC matrix, service classes, repository interfaces/projections, wire models,
error mapping, and current regression tests. A route marked implemented below
means the HTTP branch and service path exist; it does not mean every response
field is specified by the contract.

- **H:** an authorization or evidence boundary can expose another org or let
  an unauthorized role perform a security-sensitive operation.
- **M:** incorrect wire behavior, incomplete scope/audit enforcement, or a
  ratified security surface that is absent.
- **L:** documentation/serialization ambiguity or a bounded implementation
  detail with no direct security failure.

## Endpoint-by-endpoint enumeration

The contract's §3 table does not specify response bodies/statuses for every
row. The “wire” column records the current behavior so the missing contract
details remain visible rather than being treated as implied agreement.

| # | Contract method + path | Current route/service | Permission and org scope | Current wire, limits, and errors | T-250 disposition |
|---:|---|---|---|---|---|
| 1 | `POST /api/v1/orgs` (`admin-api.md:74`) | `server.ts:249-253` → `OrgService.createOrg` (`policy/services.ts:42-51`) | `org.create` at null platform target; role matrix grants only `org_admin` (`rbac.ts:34-62`). | `201 {id,name,created_at}`; body requires `name`; typed `400 validation.failed`, `403 auth.denied`, generic `500 internal`; no pagination. | Implemented; response shape is under-specified (`ADM-T250-10`). |
| 2 | `GET /api/v1/orgs/{orgId}/users` (`:75`) | `server.ts:266-269` → `OrgService.listUsers` (`policy/services.ts:128-143`) | `user.read` against the path org; null-org actors are denied for non-null targets (`rbac.ts:82-95`). | `200 {items:[...]}`; email order; `limit` default 50, clamped 1–500; batched roles; `403` cross-org, `400` invalid org. | Implemented; §3 does not document the limit/envelope (`ADM-T250-09/10`). |
| 3 | `GET /api/v1/orgs/{orgId}/devices` (`:76`, §14) | **No HTTP branch**; no `OrgRepository.listDevices` (`db/interfaces.ts:21-37`) or service method. | Required `device.read` on the path org, fail-closed null-org denial (§14.2). | Current request falls through to `404 not.found`; no response/pagination exists. | Ratified §14 surface is not implemented (`ADM-T250-08`). |
| 4 | `POST /api/v1/orgs/{orgId}/users` (`:77`) | `server.ts:261-264` → `OrgService.createUser` (`policy/services.ts:54-69`) | `user.invite` against the path org; repository duplicate is typed `ConflictError`. | `201 {id,org_id,email,created_at}`; email bound 254; duplicate → `409 conflict`; permission/validation → `403/400`; no pagination. | Implemented; body/response/status are not fully specified (`ADM-T250-10`), and unknown-org FK failures lack an explicit `not.found` path (`ADM-T250-14`). |
| 5 | `PUT /api/v1/orgs/{orgId}/users/{userId}/role` (`:78`) | `server.ts:273-280` → `OrgService.grantRole` (`policy/services.ts:71-87`) | `user.role.grant`; validates both ids and requires the user’s `org_id` to equal the path org before write. | `200 {ok:true}`; role enum validation → `400`; outsider/unknown user → `404 not.found`; no pagination. | Implemented; response/body shape is under-specified (`ADM-T250-10`). |
| 6 | `POST /api/v1/devices/{deviceId}/revoke` (`:79`) | `server.ts:322-327` → `OrgService.revokeDevice` (`policy/services.ts:106-121`) | Resolves the device’s owning org, then requires `device.revoke` on that org; cross-org is denied and audited. | `200 {ok:true}`; unknown device → `404`; denied → `403`; no pagination. | Implemented; §3 does not specify the success body (`ADM-T250-10`). |
| 7 | `POST /api/v1/orgs/{orgId}/policies` (`:80`) | `server.ts:290-303` → `PolicyService.createPolicy` (`policy/services.ts:155-198`) | `policy.write` against the path org; `auditWrap` records allowed/error/denied mutations. | Body parser accepts snake_case policy fields; `201 {id}`; 400 validation, 403 permission, 409 conflicts, generic 500; policy rules capped at 256. | Implemented; success shape and unknown-org error behavior are under-specified (`ADM-T250-10/14`). |
| 8 | `GET /api/v1/orgs/{orgId}/policies` (`:81`) | `server.ts:284-288` → `PolicyService.listPolicies` (`policy/services.ts:227-247`) | `policy.read` against the path org; cross-org/null binding fails closed. | `200 {items}`; `limit` default 50/cap 500; current rows are `{id,enabled,minTls,externalRecipients,domainRules}` and omit `name`/`org_id`; no cursor/total. | **ADM-T250-01 (M): contract promises full PolicyObject fields; code projection is camelCase/incomplete. |
| 9 | `POST /api/v1/policies/{policyId}/evaluate` (`:82`) | `server.ts:329-355` → `PolicyService.evaluate` (`policy/services.ts:213-224`) | Resolves policy owner, requires `policy.read`, and audits allow/deny/error. | `200 {verdict,reasons,evaluatedPolicyId}`; body accepts `tlsVersion`/`tls_version`; `400/403/404/500`; no pagination. | Permission/scope is fixed, but the contract does not define this response and uses `policyId` for the outbound bridge (`ADM-T250-13`). |
| 10 | `POST /api/v1/orgs/{orgId}/policies/evaluate-outbound` (`:83`, §10) | `server.ts:306-318` → `PolicyService.evaluateOutbound` (`policy/services.ts:255-297`) | `policy.read` on the path org; allowed and denied checks are audited. | `200 {orgId,overall,results[]}` with `policyId`; recipients bounded 1–256; `400/403/500`; no pagination. | Matches the §10 response/semantics; no current endpoint divergence found. |
| 11 | `POST /api/v1/mailflow/events` (`:84`, §6) | `server.ts:358-377` → `MailflowService.ingest` (`mailflow/services.ts:32-44`) and `parseMailflowIngest` (`mailflow/model.ts:46-91`) | `mailflow.ingest` at the body’s `org_id`; outbound requires non-null org; org-bound actor cannot ingest for another org. | `201 {id}`; metadata-only event is validated; `ts` is safe-integer ms; invalid `tls_version` → `400`; invalid status/verdict silently becomes `unknown`; `403/400/500`; no pagination. | Core scope is correct; enum strictness and response/status details need a contract ruling (`ADM-T250-11/10`). |
| 12 | `GET /api/v1/mailflow/events` (`:85`) | `server.ts:379-390` → `MailflowService.query` (`mailflow/services.ts:46-62`) | `mailflow.read`; org-bound caller defaults to its own org, explicit other org is denied. | `200 {items: MailflowEvent[]}`; accepts `org`, `recipientDomain`, `since`, `until`, `limit` (default 50, cap 1000); no cursor/total; `403/400`. | Current default/filter names are not fully specified in §3 (`ADM-T250-09/10`); scope fix is present. |
| 13 | `GET /api/v1/audit` (`:86`, §7) | `server.ts:411-420` → `AuditService.query` (`mailflow/services.ts:125-144`) | `audit.read`; org-bound caller defaults to its own org; explicit other org is denied. | `200 {items}`; limit default 50/cap 1000; returns only `{seq,ts,actor_subject,action,outcome,details}`; `details` is a JSON string and hashes/org/resource/request fields are omitted; `403/400`. | **ADM-T250-02 (M): response is a lossy projection, not the contract AuditRecord shape; read denial is not audited (`ADM-T250-04`). |
| 14 | `GET /api/v1/audit/verify` (`:87`, §7) | `server.ts:398-401` → `AuditService.verify` (`mailflow/services.ts:156-167`) | Requires `audit.read` at null target; no org filter is allowed because verification is chain-wide. | `200 {valid,checked,error}`; accepts `limit` default 1000, floors at 1, caps at 10,000; `limit` can verify only a prefix; `400/403`; no cursor. | **ADM-T250-03 (M): §7/§13 full-chain honesty conflicts with a bounded prefix attestation; denial is not audited (`ADM-T250-04`). |
| 15 | `GET /api/v1/audit/export` (`:88`, §13) | `server.ts:403-409` → `AuditService.export` (`mailflow/services.ts:181-217`) | Requires `audit.export` at null target, but current RBAC grants that permission to `org_admin`; `system-admin` is absent from the TypeScript role union (`types.ts:3-9`, `rbac.ts:34-62`). | `200 application/x-ndjson`, no-store; full range up to 10,000, filters ignored/unsupported; cap → `400 validation.failed`; denial → `403`; storage → generic `500`; success self-audits, denials do not. | **ADM-T250-05 (H): global export is available to org_admin, contrary to ratified system-admin-only rule. ADM-T250-06 (M): export denials are not audited. |
| 16 | `GET /api/v1/orgs/{orgId}/audit/export` (`:89`, §13.0) | **No HTTP branch or service method** exists. | Future route must require path-scoped `audit.export`, force `orgId == actor.orgId`, and never return another org’s rows (§13, §14-style rules). | Current request falls through to `404 not.found`; no scoped artifact or pagination exists. | **ADM-T250-07 (M): ratified org-scoped export is not implemented; code-fix required. |
| extra | `GET /healthz` | `server.ts:238-240` | No permission; explicitly extra-contract supervision route. | `200 {status,service,version,contract}`; current version is `admin-api/1.3`. | No current drift; keep documented as extra-contract. |

## Divergence findings and recommendations

| ID | Contract promise vs current code | Evidence | Severity | Code-fix vs contract-fix recommendation |
|---|---|---|---|---|
| **ADM-T250-01** | §3 says policy listing returns full PolicyObject definitions; current list projection is camelCase and omits `name` and `org_id`. | `admin-api.md:81,129-143`; `server.ts:284-288`; `policy/services.ts:227-247`; `policy/model.ts:11-19` | M | **Code-fix:** serialize the full contract shape (or deliberately amend §3/§5.1 with Lead review). Do not silently rely on the current asymmetric POST/GET shape. |
| **ADM-T250-02** | §7 defines a full audit record; `GET /audit` returns a lossy summary and stores `details` as a JSON string. | `admin-api.md:202-230`; `server.ts:411-420`; `mailflow/services.ts:72-79,136-143`; `audit/model.ts:23-37` | M | **Code-fix:** return the full record or add an explicit contract-level summary projection with documented field semantics. |
| **ADM-T250-03** | Audit verification is a hash-chain integrity operation; current route accepts a bounded `limit` and can call `verifyChain` on a prefix while returning `valid:true`. | `admin-api.md:223-230,397-409,508-524`; `server.ts:398-401`; `mailflow/services.ts:156-167`; `audit/export.ts:114-136` | M | **Code-fix:** remove the public `limit`/always verify the full chain, or return an explicit incomplete/coverage field and never label a prefix as full-chain valid. |
| **ADM-T250-04** | §1 requires every authorization denial to be audited; list/read services call bare `requirePermission`, and `AuditService` explicitly does not audit read/verify denials. | `admin-api.md:30-33,67-68`; `policy/services.ts:123-126,227-229`; `mailflow/services.ts:54-61,125-129,156-158`; `services.ts:122-153` | M | **Code-fix:** add denial-only audit paths for every read, including audit query/verify and future device/export routes; never record a denied read as allowed. |
| **ADM-T250-05** | §2/§13 make global `audit.export` a distinct platform `system-admin` permission; current `OrgRole` has no system-admin and `org_admin` holds `audit.export`, so a global export succeeds. | `admin-api.md:42-55,413-458`; `types.ts:3-9`; `rbac.ts:34-62,82-95`; `server.ts:403-409`; `mailflow/services.ts:181-182` | H | **Code-fix:** add a distinct system-admin role/permission check, deny org_admin on the global route, and add regression coverage for global versus org-scoped scope. |
| **ADM-T250-06** | §13.4 requires export denial rows and says a failed self-audit must prevent the body; current `export` checks permission and appends only after a successful build, with no denial append. | `admin-api.md:526-550`; `mailflow/services.ts:181-217` | M | **Code-fix:** implement a denial-only audit path and make an audit-append failure return sanitized `500 internal` without sending NDJSON. |
| **ADM-T250-07** | §13.0/§13.4 ratify `GET /api/v1/orgs/{orgId}/audit/export`; no route, service, or repository method exists. | `admin-api.md:88-89,413-431`; `server.ts:249-425`; `mailflow/services.ts:91-219`; `db/interfaces.ts:91-122` | M | **Code-fix only:** implement the path-scoped service/route, enforce `orgId == actor.orgId`, and append an org-scoped `audit.export` row. |
| **ADM-T250-08** | §14 ratifies the device inventory route, `DeviceView` projection, bounded limit, ordering, duplicate-label rule, scope, and denial audit; none exists. | `admin-api.md:669-831`; `server.ts:256-320`; `db/interfaces.ts:21-37`; `policy/services.ts:89-121` | M | **Code-fix only:** follow the §14.5 checklist: repository list method, service permission/scope/denial path, route/parser, and tests. `createDevice` currently has no route and is incorrectly gated on `device.revoke` (`policy/services.ts:89-103`). |
| **ADM-T250-09** | Existing user/policy list routes have `limit` default 50/cap 500, but §3 does not state those bounds or the list envelope. | `admin-api.md:75,81`; `server.ts:266-288`; `policy/services.ts:128-143,227-247` | L | **Contract-fix:** document the implemented limit, ordering, and `{items}` envelope, or make the service/route match a newly approved pagination contract. |
| **ADM-T250-10** | §3 specifies service/permission for most rows but not request bodies, success statuses, or response serialization; current routes return several undocumented shapes (`{ok:true}`, `{items}`, `{id}`, and policy/audit projections). | `admin-api.md:70-97`; `server.ts:249-305,322-420` | L | **Contract-fix:** add bounded wire request/response examples and status codes to §3, including the exact error envelope behavior. Preserve current code while the contract is amended. |
| **ADM-T250-11** | §6 enumerates `security_status` and `policy_verdict`; invalid values are silently coerced to `unknown`, while invalid `tls_version` is rejected. The §3/§6 request/response behavior does not state this asymmetry. | `admin-api.md:177-200`; `mailflow/model.ts:54-73`; `server.ts:360-375` | L | **Decision gate:** either document unknown-value defaulting consistently (aligning the invariant that unknown enum values are ignored) or make all invalid enum values `400 validation.failed`; do not change this in a read-only audit. |
| **ADM-T250-12** | The single-policy evaluate route returns `evaluatedPolicyId`, while the outbound route and §10 use `policyId`; the §3 contract does not define the single-evaluate response. | `admin-api.md:82,268-317`; `server.ts:329-355`; `policy/model.ts:29-33`; `policy/services.ts:213-224` | L | **Contract/code decision:** standardize the field (likely `policyId`) and document the request/response, or explicitly define the single-evaluate projection. |
| **ADM-T250-13** | Stable `not.found` is listed for missing resources, but user/policy creation has no explicit org existence check; invalid/nonexistent path orgs can reach FK/driver failures and become generic `500`. | `admin-api.md:91-97`; `policy/services.ts:54-69,155-198`; `server.ts:257-303`; `repositories.ts:84-100,246-266` | L | **Code-fix:** validate the path org and map an absent org to `404 not.found` (or document the chosen conflict/internal behavior). Keep identifier validation before repository writes. |
| **ADM-T250-14** | §4 describes `audit_log.seq` as `PRIMARY KEY AUTOINCREMENT`; current SQLite/Postgres schemas use an app-assigned ordinary primary key and the repositories deliberately assign contiguous sequence values in a transaction. | `admin-api.md:112-127`; `db/schema.sqlite.ts:140-157`; `db/schema.pg.ts:141-160`; `db/repositories.ts:365-405`; `db/repositories.pg.ts:341-386` | L | **Contract-fix:** describe the app-assigned contiguous sequence and transaction invariant; do not restore AUTOINCREMENT/DB-generated numbering without changing the hash-chain contract. |
| **ADM-T250-15** | Service-only `listDomains` and `createDevice` operations have no HTTP route; `createDevice` is gated with `device.revoke` rather than a declared `device.create`. | `policy/services.ts:89-126`; `db/interfaces.ts:21-37`; `server.ts:256-320`; §14.6 (`admin-api.md:824-831`) | L/M | **Code-fix/decision:** either add explicit routes and permission definitions, or keep them internal and correct the misleading create-device gate; §14 currently ratifies the read route only. |

## §13 audit export — current status

The implemented global route is present and its artifact format is mostly
aligned with §13: `server.ts:403-409` returns raw NDJSON through
`sendNdjson` (`server.ts:45-56`), and `audit/export.ts:114-170` emits the
header, records, chain state, and signed/unsigned trailer. The full-chain cap,
`application/x-ndjson`, `no-store`, signed/unsigned behavior, and generic
storage-error envelope are present.

The blocking drift is authorization: `OrgRole` has no `system-admin`
(`types.ts:3-9`), while `rbac.ts:34-50` grants `audit.export` to `org_admin`.
Because `AuditService.export` checks a null target (`mailflow/services.ts:181-182`),
an org-scoped org_admin can currently obtain the global whole-chain artifact.
The future org-scoped route and its service are also absent. See
`ADM-T250-05`–`07`; the contract is ratified, so these are code-fix items, not
permission to weaken §13.

## §14 device inventory — current status

`GET /api/v1/orgs/{orgId}/devices` has no route, service, or repository list
method. The only device operations are `createDevice` and `revokeDevice` in
`policy/services.ts:89-121`; `createDevice` has no HTTP route and uses the
wrong permission name for creation. The §14 wire shape, limit 50/cap 500,
`created_at,id` ordering, `revoked_at` projection, duplicate normalized-label
rule, fail-closed `device.read` scope, and denial-only `device.list` audit row
are therefore all implementation requirements, not current behavior. Follow
`ADM-T250-08` and the §14.5 checklist; do not reinterpret the current
`kiwi-app` in-memory device registry as this org inventory.

## Current T-193 fixes verified (not current findings)

The current source/tests show the following earlier defects resolved:
authenticated/audited policy evaluation; fail-closed null-org RBAC; owner-scoped
device revocation; explicit `org.create`; non-positive `verify` limits rejected;
atomic/capped policy creation with error audit rows; typed 404/409 errors;
cross-org role membership checks; bounded/batched list methods; millisecond
timestamps; transaction-serialized audit appends; escaped LIKE filters; strict
`numParam`; JSON content-type enforcement; and the corrected healthz contract
string. The audit retains the remaining full-chain, response-shape, system-admin,
denial-audit, and §13/§14 implementation gaps above.

## Cross-surface notes

- `GET /healthz` is intentionally extra-contract (`server.ts:238-240`); it has
  no actor/permission and should remain a process-supervision endpoint.
- `POST /api/v1/policies/{policyId}/evaluate` and audit verify/export are
  current route branches, but their permission, scope, or evidence semantics
  must be read together with the service methods; route presence alone is not
  proof of contract conformance.
- Error mapping in `server.ts:195-216` now produces the uniform JSON envelope
  for typed authorization, validation, not-found, conflict, and generic errors;
  endpoint-specific gaps above are about which service errors reach that mapper,
  not a missing global mapper.
