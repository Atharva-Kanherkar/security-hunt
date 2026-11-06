# Common checklist (every target)

Item format: tier, yield, standards, where it applies, how to hunt, how to
prove (oracle IDs from `oracles.md`), when to kill it, and real cases from
`cases.md`. Grep patterns are starting points; read the code they land on.

---

## CMN-01 Variants of past security fixes
Tier S-A (inherits the original bug) · Yield high · Maps: the original fix's CWE

**Applies:** any repo with history, published advisories, or a CHANGELOG.

**Hunt**
1. List fixes: the fingerprint's security-commit list, then the advisories
   themselves if the fingerprint counted any and you are online
   (`gh api repos/<o>/<r>/security-advisories`; each names its fix commit), CHANGELOG and release-note entries that mention security, and the
   commits just before patch releases. Commit messages often hide fixes
   ("prevent unbounded recursion", "handle drive-relative paths"), so read the
   patch-release diffs too. On a shallow clone, `git fetch --unshallow` first if allowed.
2. For each fix, read the diff and write the root cause in one line ("handler
   trusted `X-User` from the request", "join() allowed `..` after decoding").
3. Search for the same pattern elsewhere: sibling handlers, other parsers,
   other platforms (Windows paths, case-insensitive filesystems), the other
   direction (read vs write, import vs export), older API versions still mounted.
4. Check the fix itself: does it cover encodings, symlinks, races, alternate
   entry points? Many CVEs are bypasses of an earlier fix.

**Prove:** the oracle for the original class.
**Kill if:** the sibling path is unreachable from an entry point, or it goes
through the same now-fixed helper.
**Cases:** C06, C07, C16 (fix bypasses), Big Sleep SQLite, Claude/GhostScript.

---

## CMN-02 Skipped invariant (sibling inconsistency)
Tier S · Yield high · Maps: A01:2025, CWE-862, CWE-863, ASVS V8

**Applies:** any codebase with a shared guard: `requireAuth`, `canAccess`,
`authorize`, `@login_required`, `before_action`, policy objects, RLS, ORM
scopes, an `assertOwner` helper.

**Hunt**
1. Find the guard and count its call sites. List the routes, commands, jobs and
   RPC methods that touch the same resource type.
2. Diff the two lists. The interesting ones: list vs get, export/download/bulk
   vs single, v1 vs v2, web vs API/CLI/MCP/webhook, sync vs async job, GraphQL
   resolver vs REST handler, admin "impersonation" helpers, alias routes.
3. Look at recent hardening commits: the guard was usually added to the place
   someone reported, not to its siblings.
4. A guard can be a mode or feature flag rather than an auth check: demo or
   safe mode, read-only mode, sandbox on/off, "challenge enabled". When a past
   fix added such a gate, check every sibling sink for the same gate, and both
   branches of each gate.
5. In libraries the shared guard is the sanitizer or containment check, and the
   siblings are: sync vs async APIs, streaming vs buffered, `path` vs
   `linkpath` (or any second field with the same meaning), per-platform
   branches (Windows, case-insensitive filesystems), old vs new options.

**Prove:** O-AUTHZ against the unguarded sibling, with the guarded sibling as the control.
**Kill if:** the sibling is protected another way you had not read (middleware
mounted on the router, ORM default scope, DB row-level security, gateway); or a
merged PR records the difference as deliberate (gates.md "already decided").
**Cases:** C01.

---

## CMN-03 Fail-open on errors and unknown input
Tier A-S · Yield medium · Maps: A10:2025 Mishandling of Exceptional Conditions, CWE-636, CWE-703, CWE-754, CWE-280

**Applies:** every guard, parser, verifier and policy check.

**Hunt**
- `catch`/`except`/`rescue`/`if err != nil` around a check that then continues,
  returns `true`/`nil`/`allow`, or logs and proceeds.
- Default branches: `switch` with `default: allow`, unknown role or scope
  treated as no restriction, missing config meaning "allow all".
- Deny-lists where an allow-list was needed (blocked hosts, blocked commands,
  blocked file names, blocked HTML tags).
- Verification functions whose error path returns success, or whose result is
  ignored (`verify(...)` called, return value unused).
- Timeouts and partial failures: the auth service is unreachable, so the
  request goes through.

**Prove:** trigger the error or unknown value as the attacker and show the
protected action happens (O-AUTHZ / O-AUTHN), control: the normal value is denied.
**Kill if:** the attacker cannot cause the error condition; the fail-open path
only affects the attacker's own data.

---

## CMN-04 Parser differentials and canonicalization order
Tier S-A · Yield medium · Maps: CWE-436, CWE-180, CWE-20, ASVS V1/V2

**Applies:** anything that checks a value with one parser and uses it with
another: URLs, paths, hostnames, emails, JSON (duplicate keys), XML/SAML,
multipart, HTTP headers, Unicode, YAML, shell words, MIME types.

**Hunt**
- Validate-then-normalize: the check runs before decoding, lowercasing, NFC/NFKC
  normalization, path resolution, or symlink resolution.
- Two parsers for one input: a validator library vs the HTTP client, a regex vs
  `new URL()`, REXML vs Nokogiri, the proxy vs the app, Python vs Go JSON.
- Read vs write asymmetry: a value is stripped or unescaped on read but written
  back raw (git CR bug).
- `startsWith(base)` path containment without a trailing separator or after
  `..` resolution; host checks with `endsWith("example.com")`.

**Prove:** one input that passes the check and is used differently; the oracle
for the resulting class. Control: the plain malicious input is blocked.
**Kill if:** both sides actually share one parsed object.
**Cases:** C04, C06, C25.

---

## CMN-05 Internal-only signals accepted from outside
Tier S · Yield medium · Maps: A01:2025, CWE-290, CWE-346, CWE-807

**Applies:** apps behind proxies, gateways, middleware chains, service meshes,
frameworks with internal headers. Usually `n/a` for library-only targets.

**Hunt**
- Identity or routing from headers: `X-User-Id`, `X-Forwarded-For/Host/Proto`,
  `X-Original-URL`, `X-Rewrite-URL`, `X-Internal`, `X-Middleware-*`, `Via`,
  `X-Real-IP` used for allowlists, rate-limit identity or auth decisions.
- "Internal" flags in request bodies (`is_internal`, `skip_auth`, `system: true`).
- Service-to-service endpoints on the public router, or a gateway that injects
  identity but does not strip the client's copy.

**Prove:** send the header or flag from outside as an unauthenticated client;
O-AUTHZ / O-AUTHN. Control: without it, denied.
**Kill if:** the edge proxy in deployed config strips or overwrites the header
(read the infra config, not assumptions; say which config you read).
**Cases:** C01, C03.

---

## CMN-06 Secrets or other users' data returned to a caller
Tier A-S · Yield medium · Maps: A01/A04:2025, API3:2023, CWE-200, CWE-201, CWE-209, ASVS V14

**Applies:** any API, CLI output, log endpoint, error page, client bundle.
Usually `n/a` for library-only targets.

**Hunt**
- Serializers that dump whole models (`toJSON`, `serde(Serialize)` on DB rows,
  `model_to_dict`, `render json: @user`): API keys, password hashes, tokens,
  integration secrets, other members' emails.
- Error responses including stack traces with secrets, SQL, or internal URLs.
- Build-time env vars bundled into the client (`NEXT_PUBLIC_`, `VITE_`,
  `REACT_APP_`) that hold real secrets.
- Logs or audit trails readable by lower roles that contain tokens.

**Prove:** the lower-privileged caller receives the field; show the field is
populated in a realistic row (an `omitempty` empty value is not a leak) and
what it can be used for.
**Kill if:** the field is empty in practice, or the caller is entitled to it.
Secrets on disk or in env are excluded (gates.md).

---

## CMN-07 Known-vulnerable dependency on a reachable path
Tier per advisory · Yield medium · Maps: A03:2025 Software Supply Chain Failures, A06:2021, CWE-1395

**Applies:** every lockfile.

**Hunt**
1. Resolve exact versions from lockfiles (not ranges in manifests).
2. Check them against advisories (`npm audit --json`, `pip-audit`, `cargo audit`,
   `govulncheck`, `osv-scanner`, GHSA). `govulncheck` reports reachability; for
   the rest, find whether the vulnerable function or feature is called.
3. Focus on framework-level bugs that are reachable by default (RSC Flight,
   middleware, template engines, XML parsers, archive libraries, model loaders).

**Prove:** the vulnerable code path runs from the target's own entry point with
its own config (O-DESER, O-CMDI, etc.). A version match alone is not a finding;
it is what Dependabot already reports.
**Kill if:** the vulnerable function is never called, or the feature is off.
**Cases:** C02, C15.

---

## CMN-08 Dangerous sink reachable from untrusted input
Tier S · Yield low-medium in framework code, higher in glue code · Maps: A05:2025 Injection, CWE-78/77/94/89/502/22/918/611/1336

**Applies:** wherever the fingerprint shows hot sinks. Trace backwards from the
sink to a source; do not report a sink without a source.

| Class | Sinks to grep | Source must be |
| --- | --- | --- |
| Command | `child_process.exec`, `execSync`, `spawn(..., {shell:true})`, `os.system`, `subprocess(..., shell=True)`, `Runtime.exec`, `exec.Command("sh","-c")`, `Command::new("sh")` | request, file content, repo content, LLM output, remote server data |
| Argument injection | `git`, `ssh`, `curl`, `tar`, `find`, `rsync`, `ffmpeg`, `zip`, `psql` called with values that can start with `-` and no `--` | same |
| Code eval | `eval`, `new Function`, `vm.runIn*`, `exec(compile())`, `ScriptEngine`, `instance_eval`, `Function(...)()` | same |
| Template (SSTI, file read) | `render_template_string`, `Template(user)`, `ejs.render(user)`, `Handlebars.compile(user)`, Velocity/Freemarker/Thymeleaf with user-built templates; also render options, layout, partial or view names taken from request data (`res.render(view, req.body)`, a `layout` option) | a template body, an engine option, or a view/partial name; not a plain template variable |
| SQL / NoSQL | raw query APIs, string-built `ORDER BY`/column/table names, Mongo filters built from JSON bodies (`$ne`, `$gt`, `$where`) | request |
| Deserialization | `pickle`, `yaml.load` (non-safe), `Marshal.load`, `ObjectInputStream`, `BinaryFormatter`, `node-serialize`, `torch.load`, `joblib.load` | bytes an attacker supplies |
| XML | parsers with external entities or DTDs enabled | uploaded or fetched XML |
| Path | `path.join(base, user)`, `sendFile`, `open(user)`, archive members | request, archive entries, remote metadata |

**Prove:** O-CMDI, O-DESER, O-PATH, O-SQLI, O-SSTI from the public entry point.
**Kill if:** the value is constant or validated by an allow-list that holds
after normalization; the "sink" API name is a lookalike (check what it does;
Sifting the Noise FM3: agents report XSS on `format()` calls that escape).

---

## CMN-09 Identity keyed on a mutable or unverified attribute
Tier S · Yield medium · Maps: A07:2025, CWE-287, CWE-290, ASVS V6/V10

**Applies:** SSO, OAuth/OIDC, SAML, magic links, invites, webhooks, account
linking, multi-provider login. For libraries, only auth and identity libraries.

**Hunt**
- Users looked up by `email` from an IdP token (`email` claim, unverified or
  from a multi-tenant IdP) instead of the stable `sub` + issuer (+ tenant id).
- Account linking that merges a new provider login into an existing account by
  matching email.
- Webhooks or callbacks that take the acting user's identity from payload
  fields (`user_email`, `actor`) instead of an authenticated channel.
- Invite or reset tokens not bound to the account or email they were issued for.

**Prove:** O-AUTHN: the attacker controls an identity whose email equals the
victim's (own IdP tenant, unverified email, test provider) and lands in the
victim's account.
**Kill if:** the IdP guarantees verified, non-reassignable emails for this
issuer and the app restricts issuers; say which config shows that.
**Cases:** C05.
