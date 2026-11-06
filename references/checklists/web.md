# Web (browser-facing) checklist

For apps that serve pages or a SPA to browsers: sessions, cookies, rendering,
cross-origin behaviour, SSR frameworks. Always load `api.md` alongside: the
server side of a web app is an API. Standards: OWASP Top 10 2025, ASVS 5.0
V3 (Web Frontend), V6/V7/V10, WSTG CLNT/SESS/ATHN.

---

## WEB-01 Authorization enforced only at an edge layer
Tier S · Yield high · Maps: A01:2025, CWE-602, CWE-288, ASVS V8

**Hunt**
- Auth only in framework middleware or route guards, with handlers that do not
  re-check: Next.js `middleware.ts` matchers, Nuxt/SvelteKit hooks, Express
  `app.use` ordering, Django URL decorators missing on one view.
- Matcher gaps: middleware `matcher` patterns that miss trailing slashes,
  encoded paths, locale prefixes, `/_next/data/...`, API routes, or route groups.
- **Server Actions, loaders and RPC-style functions are public POST endpoints.**
  Every `"use server"` export, Remix `action`/`loader`, SvelteKit form action,
  tRPC procedure and Nuxt server route must authorize inside itself. Hidden UI
  is not a guard.
- Frontend-only checks: role flags in the client bundle, disabled buttons,
  route guards in the SPA router.

**Prove:** call the handler, action id, or data route directly without the edge
layer's conditions (O-AUTHZ / O-AUTHN); control: the page route behind the
middleware redirects to login.
**Kill if:** the handler re-checks; the framework version is not affected by a
known bypass (check the lockfile).
**Cases:** C01, C02.

---

## WEB-02 Login, reset, OAuth and account linking
Tier S · Yield medium-high · Maps: A07:2025, CWE-287, CWE-640, CWE-601, CWE-352, ASVS V6/V10

**Hunt**
- Password reset: token in a link built from the `Host` header; token reusable,
  long-lived, or not bound to the user; reset that logs in without
  invalidating other sessions.
- Email change without re-authentication; email verification that can be
  completed for an address the attacker does not own.
- OAuth/OIDC: missing or unbound `state`; `redirect_uri` allowed by prefix or
  wildcard, combined with any open redirect on an allowed host (token theft);
  `nonce` not checked; account linking by unverified email (CMN-09).
- MFA bypass: the second factor checked on one login path but not on SSO, API
  key creation, or the "remember device" path.

**Prove:** O-AUTHN: attacker ends in the victim's session or account.
**Kill if:** the flow requires something only the victim has and the attack
needs it.
**Cases:** C05.

---

## WEB-03 XSS where the victim matters
Tier A (S if it reaches admin sessions or a privileged desktop bridge) · Yield medium · Maps: A05:2025, CWE-79, ASVS V1/V3

**Hunt**
- Raw HTML sinks fed by other users' content: `dangerouslySetInnerHTML`,
  `v-html`, `{@html}`, `innerHTML`, `|safe`, `mark_safe`, `html_safe`,
  `bypassSecurityTrust*`, triple-stash `{{{ }}}`.
- Markdown or rich-text renderers without a sanitizer, or with `allowDangerousHtml`;
  `javascript:` and `data:` URLs in user-controlled `href`/`src`.
- Uploaded SVG/HTML served inline from the app origin (API-10).
- LLM output rendered as HTML or markdown (AGT-04).
- Stored content shown to admins or support staff (privileged victims).

**Prove:** O-XSS: a headless browser, logged in as the victim, executes the
payload's canary function. Reflected text is not proof.
**Kill if:** the framework escapes this context; a strict CSP blocks execution
in the deployed config (test with the real header); only the attacker sees it
(self-XSS, excluded).

---

## WEB-04 CSRF on state-changing actions
Tier B-A · Yield low-medium · Maps: A01:2025, CWE-352, ASVS V3

**Hunt**
- Cookie-authenticated endpoints that change state on GET, or accept
  `application/x-www-form-urlencoded`/`text/plain`/`multipart` bodies without a
  CSRF token or Origin check.
- Cookies with `SameSite=None`, or apps on a shared parent domain where a
  sibling subdomain counts as same-site.
- Login CSRF only matters when it chains (excluded alone per gates.md).

**Prove:** a page on another origin performs the action in the victim's
browser (headless browser, real cookies, real SameSite).
**Kill if:** `SameSite=Lax/Strict` blocks the request method used; auth is a
bearer header, not a cookie.

---

## WEB-05 CORS that grants credentials to other origins
Tier A · Yield medium · Maps: A02:2025, CWE-942, CWE-346, ASVS V3

**Hunt**
- `Access-Control-Allow-Origin` reflected from the request `Origin` together
  with `Allow-Credentials: true`; regexes like `/example\.com$/` (matches
  `evilexample.com`); `null` origin allowed; allow-lists by `startsWith`.

**Prove:** from another origin, a credentialed `fetch` reads a victim-only
canary in a headless browser.
**Kill if:** responses with the permissive header carry no user data, or auth is
not cookie-based.

---

## WEB-06 Cache poisoning and cache deception
Tier A · Yield low-medium · Maps: A02:2025, CWE-524, CWE-349

**Hunt**
- CDN or framework caches keyed without user, cookie, or auth header on
  responses that contain user data; path-confusion (`/account/x.css`) making a
  private page cacheable.
- Unkeyed inputs that change the response (`X-Forwarded-Host`,
  `X-Original-URL`, query params excluded from the key) and get cached for others.
- Framework-internal caches (ISR, data cache, RSC payloads) keyed on values the
  attacker controls.

**Prove:** victim request primes the cache; an unauthenticated request reads
the victim's canary (deception), or a poisoned response is served to a clean
client (poisoning). Use a local reproduction of the cache layer, never a
production CDN.
**Kill if:** responses are `private`/`no-store`; the cache layer is not in the
deployed path.
**Cases:** C26.

---

## WEB-07 Cross-window and client-side trust
Tier B-A · Yield low · Maps: CWE-345, CWE-1385, CWE-1321

**Hunt**
- `message` event listeners without an origin check that perform actions or
  write to the DOM; `postMessage(data, "*")` with secrets.
- Client-side prototype pollution (query/hash parsers, deep merge of URL data)
  that reaches a known gadget.
- Sensitive tokens in `localStorage` combined with an XSS sink (only as a chain).

**Prove:** a page on another origin triggers the action or reads the data in a
headless browser.
**Kill if:** no reachable gadget or sensitive action (pollution alone is B at most).

---

## WEB-08 Cross-site leaks of private state
Tier B · Yield low · Maps: CWE-203, CWE-208

Only pursue when the app's model makes a yes/no answer sensitive (does this
user have a private repo named X, is this email registered in this tenant).
Techniques: response-size leaks (ETag length, cache probing), redirect leaks,
frame counting, error-event oracles.

**Prove:** a page on another origin learns the bit for the logged-in victim,
N/N, with a control account where the answer differs.
**Kill if:** the leaked bit is public or low value.
