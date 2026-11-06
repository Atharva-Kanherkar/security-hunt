# Ranking: which checklist items to run first

Every applicable item gets a score. Run them highest first. Default budget is
the top 8 to 12 items; everything else goes in the coverage table as `not run`.
A hunt that stops early with an honest coverage table beats one that skims all
60 items.

## Score = Impact + Exposure + Yield + Signal (0 to 11)

**Impact** (start from the item's tier, then adjust to this target)

| Points | Tier | Meaning |
| --- | --- | --- |
| 4 | S | Code execution on a server or a user's machine, login as any account, cross-tenant read or write |
| 3 | A | Cross-user data in one tenant, privilege escalation, credential or token theft, SSRF into the internal network, arbitrary file write |
| 2 | B | Limited disclosure (one field, metadata), XSS without privileged victims, CSRF on a minor action |
| 1 | C | Hardening. Usually excluded by `gates.md`; do not spend budget here |

**Exposure** (who can trigger it with default config)

| Points | Who |
| --- | --- |
| 3 | Unauthenticated remote, or anyone who can put content in front of the target: a page the user visits, a repo the user clones, a document or issue an agent reads. For a library: input an attacker can pass through the documented API with default options (the archive, the document, the token) |
| 2 | Any authenticated low-privilege user (self-signup, normal member, guest) |
| 1 | A privileged role, a specific non-default setting, or local access on a shared machine |
| 0 | Admin only or a disabled control. Drop it (gates.md exclusion) |

**Yield** (how often this class becomes a confirmed finding for a code-reading agent)

| Points | Classes |
| --- | --- |
| 2 | Authorization (BOLA/IDOR, function-level, tenant filters), business logic and races, auth and session flows, repo-controlled config that executes, agent tool authority and approval gaps, CI expression injection and pwn requests, variants of past fixes |
| 1 | SSRF, path traversal and archive extraction, reachable deserialization, localhost services, XSS in privileged renderers, mass assignment, webhook verification |
| 0 | SQL injection through an ORM, XXE, open redirect alone, CSRF under SameSite defaults, crypto misuse, memory corruption without a sanitizer build |

Checklist items label yield `high`, `medium`, `low`: that is 2, 1, 0. A range
such as `low-medium` rounds down.

If the item is the target's main job (extraction in an archive library,
sanitizing in a sanitizer, verification in an auth library, the approval gate
in an agent runtime), use 2 regardless of class: that is where its bugs live.

**Signal** (+1 each, from this repo)

- +1 the fingerprint shows the feature or sink (hot sink count, multi-tenant
  signals, privileged CI triggers, a local listener).
- +1 the area changed in the 90 days before the pinned commit, or a security
  fix landed in the same file or directory (`git log --oneline --since="<pinned date minus 90
  days>" <sha> -- <path>`).

Ties: run the item with the cheaper proof first (one HTTP request beats a race,
which beats a fuzzing campaign).

## Why these priors

- GitHub Security Lab audited 1,003 LLM-suggested issues: IDOR and access
  control produced more confirmed bugs than XSS and CSRF combined; business
  logic was 25% confirmed; RCE suggestions 4.2%; SQLi, XXE and open redirect 0.
  "LLMs are particularly good at finding logic bugs."
- HackerOne 2025: payouts for improper access control and IDOR are rising while
  XSS and SQLi decline.
- CWE Top 25 2025, by known-exploited (KEV) count: OS command injection 20,
  use-after-free 14, out-of-bounds write 12, deserialization 11, missing
  authentication for a critical function 11, path traversal 10. These set
  **impact and exposure**, not yield: attackers exploit them, but modern
  frameworks make them rarer in app code.
- Sifting the Noise (2026): agents filter false positives well for CWE-78, 79
  and 89, but wrongly discarded 50 to 85% of real crypto (CWE-327/328),
  trust-boundary (CWE-501) and cookie (CWE-614) findings. In those classes an
  unsure candidate is `NEEDS EVIDENCE`, never a silent drop.
- Variant analysis first: Big Sleep's first real bug and Claude's GhostScript
  bug both came from reading a past security fix and finding an unpatched
  sibling. It is the cheapest high-yield move in any repo with history.

## Default opening order per profile

After `CMN-01` (variants) and `CMN-02` (invariant skips), which always go
first. Orders list applicable items only; skip anything marked `n/a`.

| Profile | Then, in order |
| --- | --- |
| web + api | API-01, API-04, WEB-01, API-02, API-03, WEB-02, API-05, API-11, API-08, WEB-03 |
| api only | API-01, API-04, API-06, API-02, API-03, API-07, API-05, API-13, API-11, API-08 |
| cli | CLI-01, CLI-02, CLI-05, CLI-04, CLI-03, CLI-06 |
| desktop | DSK-01, DSK-02, DSK-03, DSK-04, DSK-05 |
| agent | AGT-05, AGT-02, AGT-01, AGT-03, AGT-07, AGT-04, AGT-08, AGT-09 |
| library: archive, path, filesystem | LIB-03, CMN-04, LIB-04, LIB-02, LIB-05 |
| library: sanitizer, validator, URL/HTML parser | LIB-04, CMN-04, LIB-05, LIB-02 |
| library: auth, tokens, crypto, signatures | LIB-04, CMN-03, CMN-04, LIB-05 |
| library: parser or codec in C/C++/unsafe | LIB-01, LIB-06, CMN-04, LIB-02 |
| library: other | LIB-04, LIB-03, LIB-02, LIB-01, LIB-05 |
| ci | CI-02, CI-01, CI-04, CI-05, CI-06 |

Multi-profile targets (a desktop app with an agent and a local daemon) merge
the lists and re-sort by score. The opening order is a default; the score wins.

Heavily audited targets (many published advisories, a recent run of hardening
commits) have low remaining yield. Put CMN-01 first and look for bypasses of
the newest fixes; a clean coverage table is a valid outcome.

## The plan table

Write this before hunting and keep it updated. It becomes the coverage section
of the report.

| # | Item | Score (I+E+Y+S) | Why it applies here (file:line or fingerprint line) | Status |
| --- | --- | --- | --- | --- |
| 1 | API-01 BOLA | 4+2+2+1 = 9 | 41 handlers take `:id`; `org_id` in 108 files | candidate C1 |
| 2 | CLI-01 repo config exec | 4+3+2+0 = 9 | loads `./.tool/config.toml` at startup (src/config.rs:88) | clean |
| 9 | API-11 races | 3+2+2+0 = 7 | coupon redemption in routes/coupon.ts:40 | not run |
| - | API-13 webhooks | - | no inbound webhooks (no signature headers or webhook routes) | n/a |

Status values: `clean` (ran, nothing), `candidate Cn`, `n/a` (with the reason),
`not run` (out of budget).
