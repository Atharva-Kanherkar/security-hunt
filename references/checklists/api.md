# API and server-side checklist

For any server that handles requests: REST, GraphQL, gRPC, RPC, server
actions, webhooks, background jobs triggered by requests. Web apps load this
too. Standards: OWASP API Security Top 10 2023 (API1 to API10), OWASP Top 10
2025, ASVS 5.0 V4/V6/V7/V8/V9/V10, WSTG.

Threat model to write first: who are the principals (anonymous, user, member,
admin, service, API key), what is a tenant, and which objects belong to whom.
Every item below is a question about that model.

---

## API-01 Object-level authorization (BOLA / IDOR)
Tier S · Yield high · Maps: API1:2023, A01:2025, CWE-639, CWE-862, CWE-863, ASVS V8

**Hunt**
1. Enumerate every handler that takes an object id (path, query, body, GraphQL
   argument, gRPC field, websocket message, file key, signed-URL parameter).
2. For each, find the line that binds the object to the caller (owner, member,
   tenant). Note which principal it uses.
3. Flag: lookups by id alone (`findById(id)`, `get_object_or_404(Model, pk=id)`,
   `WHERE id = ?`) followed by an action without a membership check; checks on
   the parent but not the child (`/orgs/:org/projects/:id` checks `org`, loads
   `id` from any org); checks on read but not update/delete.

**Prove:** O-AUTHZ. Two identities in two tenants; victim's object carries a
canary; attacker reads or changes it through the exact route.
**Kill if:** the check lives in middleware, an ORM default scope, a policy
layer, or DB row-level security you had not read; the object is public by
design; the only way to learn the id already requires access (then it is not a
crossing, though unguessable ids alone are not a defense).
**Cases:** GHSL data (access control is the top confirmed class).

---

## API-02 Function-level authorization (BFLA)
Tier S · Yield high · Maps: API5:2023, A01:2025, CWE-285, CWE-269, ASVS V8

**Hunt**
- Admin, staff, billing, export, impersonation, invite, role-change and
  feature-flag routes: is the role check on the route, or only in the UI?
- Method switching: `GET /users/1` guarded, `PUT`/`DELETE`/`PATCH` on the same
  path routed to a handler without the guard.
- Role from the client (`role` in body or JWT claim the client can set, `isAdmin`
  in local storage that the server trusts).
- Internal or debug routes mounted in production: `/admin`, `/internal`,
  `/debug`, `/actuator`, `/metrics`, `/graphql` playground with mutations,
  `/_next/data`, old API versions.

**Prove:** O-AUTHZ with a low-role identity calling the privileged function;
control: same call denied on the guarded sibling or for a different low role.
**Kill if:** the route is unreachable in the deployed router; the low role is
allowed by the product model (check docs and UI copy).

---

## API-03 Property-level authorization: mass assignment and over-exposure
Tier A-S · Yield high · Maps: API3:2023, A01:2025, CWE-915, CWE-213, ASVS V8/V15

**Hunt**
- Create and update handlers that pass the request body to the model
  (`Model.create(req.body)`, `update(**data)`, `.merge(params)`, `permit!`,
  `Object.assign(user, body)`, serializers with `fields = '__all__'`).
  Look for writable `role`, `org_id`, `owner_id`, `is_admin`, `verified`,
  `plan`, `credits`, `email_verified`, `tenant`.
- Responses that serialize whole objects: other users' emails, tokens, hashes,
  internal flags (see CMN-06).
- Filter, sort and search parameters that accept arbitrary field names: the
  ORM-leak class, where `?filter[password_hash][startsWith]=a` turns a search
  box into an oracle for fields the caller cannot read.

**Prove:** attacker sets a forbidden property and the server persists it (read
it back as the attacker and as an admin); or the filter oracle recovers a canary
value char by char in N requests.
**Kill if:** an allow-list (DTO, `permit(...)`, schema) drops the field;
the exposed field is public by design.
**Cases:** C23.

---

## API-04 Tenant isolation beyond the single-object path
Tier S · Yield high · Maps: API1:2023, A01:2025, CWE-668, CWE-566, ASVS V8

**Applies:** the fingerprint shows multi-tenant signals.

**Hunt**
- List, search, export, count, aggregate, report and autocomplete queries: is
  the tenant predicate always present, including in raw SQL and search-engine
  queries (Elasticsearch, Algolia, Typesense, vector stores)?
- Caches keyed without tenant or user (`cache.get(key)` where key is a slug or
  an id shared across tenants).
- Background jobs and queues: the job re-loads objects by id with no tenant,
  or runs with a service identity for the requester.
- Websocket, SSE and pub/sub subscriptions: can a client subscribe to another
  tenant's channel name?
- Token or API key scoping: is the key bound to one org, and is the request's
  org taken from the key or from a header the caller sets?
- Org switching: the current org comes from a cookie or header that is not
  re-checked against membership.

**Prove:** O-AUTHZ cross-tenant with canaries; for jobs, show the job output
lands in or reads from the other tenant.
**Kill if:** the shared data is meant to be global (public templates, catalog).

---

## API-05 Lifecycle and revocation gaps
Tier A · Yield medium-high · Maps: A07:2025, CWE-613, CWE-672, CWE-324, ASVS V7/V8

**Hunt**
- A member is removed or downgraded: do their sessions, API keys, personal
  tokens, OAuth grants, share links, invite links, webhooks and scheduled jobs
  keep working? Is membership checked at use time or only at creation?
- Password change or reset: are other sessions and refresh tokens revoked?
- Deleted or archived objects still reachable by id or through children.
- Email change: the old email can still reset the password or receive invites.
- Cached permissions with long TTLs.

**Prove:** perform the lifecycle event as the victim admin, then show the
attacker's old credential still performs a protected action N/N times; control:
a credential created after the event is denied.
**Kill if:** the product documents the persistence (e.g. links are explicitly
"anyone with the link"); the remaining access is the attacker's own data.

---

## API-06 Missing authentication on an entry point
Tier S · Yield high · Maps: API2:2023, A07:2025, CWE-306, CWE-287, ASVS V6

**Hunt**
- Diff route registration against the auth middleware: routes registered before
  the middleware, on a second router, in a plugin, or with an `exclude`/`public`
  list that is too broad (prefix matches like `/api/public*` catching
  `/api/public-admin`).
- Second transports: websocket upgrade paths, gRPC services and reflection,
  GraphQL endpoints, SSE, health/metrics/debug ports, a second listener on
  another port exposed by Docker or k8s config.
- Dangerous functions reachable without auth: code validation, preview,
  import, render, convert, "test connection" endpoints.

**Prove:** unauthenticated request performs the protected action; control: the
same request on a sibling route returns 401.
**Kill if:** the listener is bound to loopback and not exposed in deploy config;
the endpoint is intentionally public and harmless.
**Cases:** C14.

---

## API-07 Token, session and signature handling
Tier S · Yield medium · Maps: API2:2023, A07:2025, A04:2025, CWE-347, CWE-345, CWE-384, CWE-613, ASVS V7/V9

**Hunt**
- JWT: `decode` used where `verify` was meant; `alg` taken from the token
  (`none`, HS/RS confusion); missing `exp`, `aud`, `iss` checks; `kid` used as
  a file path or SQL value; JWKS fetched from a URL in the token (`jku`, `x5u`).
- Signature checked over one representation and data read from another
  (signature wrapping; signed body vs parsed body; signed URL path vs routed path).
- Session fixation (session id not rotated at login), sessions valid after
  logout, predictable tokens (`Math.random`, timestamps, sequential ids).
- Secret comparison with `==` on HMACs and API keys (timing; only report with a
  practical oracle, otherwise hardening).
- Password reset: token not bound to user, not single-use, no expiry, reset link
  built from the `Host` header (poisoning).

**Prove:** O-AUTHN: forge or replay a token and act as the victim.
**Kill if:** the library enforces the check by default for this config (read
the library version's code, not its docs).
**Cases:** C04.

---

## API-08 Server-side request forgery
Tier A-S · Yield medium · Maps: A01:2025 (SSRF merged), API7:2023, CWE-918, ASVS V1/V12

**Hunt**
- Every server-side fetch whose URL or host comes from a request: link
  previews, webhooks (outbound), import-from-URL, image/PDF/screenshot
  renderers, OAuth/OIDC discovery, SAML metadata, avatar URLs, MCP/plugin
  endpoints, "test connection" buttons.
- Absolute URLs built from `Host` or `X-Forwarded-Host` and then fetched.
- Deny-list validators: decimal/octal/IPv6 forms, `0.0.0.0`, `[::ffff:127.0.0.1]`,
  DNS names that resolve to private IPs, DNS rebinding between check and use,
  redirects followed after the check, and redirect loops that reveal blind
  responses.

**Prove:** O-SSRF: a local canary listener on a private address receives the
request; for impact, a fake metadata service returns a canary the attacker reads.
**Kill if:** the fetch runs in an egress-restricted worker (cite the config);
the response is never observable and no internal side effect exists
(blind SSRF with no impact is B at most).
**Cases:** C03, C27.

---

## API-09 Injection in handlers
Tier S · Yield low-medium · Maps: A05:2025, CWE-89, CWE-943, CWE-1336, CWE-78, CWE-611, CWE-90

See CMN-08 for sinks. API-specific places to look: dynamic `ORDER BY` and
column names, JSON bodies turned into Mongo or Elasticsearch queries,
GraphQL arguments passed into raw queries, report builders, template-based
emails or PDFs with user-authored templates (SSTI), XML/SOAP endpoints.

**Prove:** O-SQLI / O-SSTI / O-CMDI. Error-based and boolean differentials need
the N/N rule plus a control; timing alone is `NEEDS EVIDENCE`.
**Kill if:** parameterized end to end; ORM escaping of the exact construct.
**Cases:** C24.

---

## API-10 File upload, download and storage keys
Tier A-S · Yield medium · Maps: A01/A05:2025, CWE-434, CWE-22, CWE-73, ASVS V5

**Hunt**
- Storage keys or paths built from filenames or ids without tenant prefixes;
  signed URLs that sign a prefix, never expire, or are generated for any key
  the caller names.
- Path traversal in filename, archive entries, or `key` parameters.
- Uploaded HTML/SVG/XML served from the app origin with a sniffable or
  attacker-chosen content type (stored XSS, see WEB-03).
- Server-side processing of uploads (ImageMagick, ffmpeg, LibreOffice, PDF
  parsers, zip extraction) with known-dangerous features.

**Prove:** O-PATH (read or write a canary outside the intended prefix) or
O-AUTHZ (download another tenant's file by key).
**Kill if:** keys are random and tenant-scoped and the signing endpoint checks
ownership.
**Cases:** C13, C16.

---

## API-11 Business logic and races
Tier A · Yield high · Maps: API6:2023, A06:2025 Insecure Design, CWE-840, CWE-362, CWE-367, ASVS V2

**Hunt**
- Limits enforced by read-then-write without a lock or unique constraint:
  coupons, credits, seats, invites, votes, single-use tokens, withdrawals,
  "one free trial". The single-packet attack makes these practical.
- State machines that can be skipped or replayed (pay -> ship, approve -> merge,
  verify -> activate) by calling a later step directly.
- Negative or huge quantities, currency/rounding, client-supplied prices or
  totals, trusting client timestamps.
- Approval flows where the approved thing can change after approval (approve by
  id, execute by latest content).

**Prove:** O-RACE (limit exceeded M of N runs, sequential control never exceeds)
or a direct-call sequence showing the skipped step.
**Kill if:** a DB constraint or transaction makes it impossible (show the
constraint); the effect only benefits the attacker against their own quota
with no cost to others (then it is a product decision, not security).
**Cases:** C28.

---

## API-12 GraphQL specifics
Tier A-S · Yield medium · Maps: API1/API3/API5:2023, CWE-639, CWE-285

**Hunt**
- Authorization per resolver and per field, not only on the root query.
  Nested traversal (`me { org { members { apiKeys } } }`, `node(id:)` global
  lookups) reaching other tenants' objects.
- Mutations missing the guard that the equivalent REST route has (CMN-02).
- Batching and aliases only matter when they defeat a security control (OTP or
  login attempt limits).

**Prove:** O-AUTHZ via the GraphQL path; control via REST or the guarded field.
**Kill if:** introspection being on is not a finding; depth/complexity limits
are DoS (excluded).

---

## API-13 Inbound webhooks and callbacks
Tier A-S · Yield medium · Maps: A07/A08:2025, CWE-345, CWE-347, CWE-290

**Hunt**
- Signature verification: missing, optional when the header is absent,
  computed over parsed-then-reserialized JSON, compared with `==`, using a
  shared secret that is empty in deployed config.
- Identity from payload: the webhook acts as the user named in the body
  (email, external id) without proving the sender owns that identity.
- Replay: no timestamp or nonce check on side-effecting events.
- OAuth callbacks: `state` missing or not bound to the session; `redirect_uri`
  matched by prefix; codes accepted for a different client.

**Prove:** send an unsigned or forged event as an outsider and show the side
effect; control: the legitimate signed event works, a wrong signature is
rejected on the guarded sibling.
**Kill if:** the endpoint is only reachable from the provider's IP range in
deployed config (cite it) and the payload identity is provider-verified.
**Cases:** C05.

---

## API-14 Unsafe consumption of upstream APIs
Tier A · Yield low-medium · Maps: API10:2023, A08:2025, CWE-20, CWE-345

**Hunt**
- Data from a third-party API or provider treated as trusted: redirects
  followed to internal hosts, identity or role taken from an upstream profile,
  HTML from an upstream rendered unsanitized, upstream file names used as paths.

**Prove:** a local fake upstream returns the malicious value; the oracle for the
resulting class.
**Kill if:** the upstream is first-party and authenticated, and compromising it
is out of the threat model.
