---
name: security-hunt
description: Find real, verified security bugs in a codebase with no false positives. Runs the kairo three-gate method (correctness, usefulness, upstream status) as a phased workflow - hunt candidates, prove each with a faithful repro and control, have an independent agent try to falsify it, then report only survivors. Use when asked to "find security issues", "security hunt", "bug hunt", "kairo hunt", "audit this repo for vulns", "find a real security bug", or to verify/triage a suspected vulnerability or someone else's security finding.
---

# security-hunt

Goal: every finding this skill reports is **real, reachable, reproduced, and matters**.
Zero findings is an acceptable, honest result. A wrong finding is worse than none:
it costs maintainer trust and the next real report gets ignored.

The model is a candidate generator, never the authority. A candidate becomes a
finding only after execution evidence plus an independent falsification attempt.

Read `references/gates.md` before Phase 3. If a project notes file exists for
the target (`references/<project>.md`, see `references/project-notes.example.md`),
read it too: it holds past real bugs, already-tracked issues, where to search
upstream, and how to run repros for that codebase.

## Hard rules

- **Authorized targets only.** Your own repos/worktrees, local emulators, fake
  upstreams, and staging with synthetic identities. Never prod data, never real
  user content, never another tenant, never a live destructive action (no real
  commit/merge/delete/payment to "prove" impact; trace the last hop instead).
- Never print, copy, or persist a credential. Env var names only.
- Work on a pinned commit of the latest default branch (`git fetch` then a detached
  worktree). Record the SHA. Findings on stale code are invalid.
- **Check upstream before you hunt.** Once Phase 1 ranks candidates, run the
  Phase 5 upstream search on each top candidate BEFORE tracing or proving. If
  the issue is already filed upstream (open issue, fix PR, or maintainer
  ruling), do NOT hunt it: record the tracker link + status in one line and
  move on. Hunt only novel candidates, unless the user explicitly asks for a
  repro to strengthen an existing static-only report.
- Repro tests are scratch: name them `zz_*_repro_test.*`, never commit them.
- Do not file, comment, label, or message anyone without the user's explicit ask.
  Hand over drafts.
- Plain language. State what was NOT verified.

## Workflow

Track progress with a task list. Each phase has an exit criterion; do not skip.

### Phase 0 - Scope and threat model (5 min)

1. Pin the target: repo, SHA, date. Fetch latest default branch.
2. Write the product's security model in 5 lines: tenants, roles, who may see/do
   what, trust boundaries (user to API, API to sandbox/agent, service to service,
   LLM output to tools). Source it from code (authz helpers, middleware) and docs,
   not assumptions.
3. List the **intended invariants** the code itself states: authz helpers used
   everywhere (e.g. `canAccess(user, resource)`, `requireRole`), comments like
   "only the owner may delete", deny-lists, recent
   hardening commits.
   The best bugs are places that skip an invariant the codebase enforces elsewhere.

Exit: a written model + invariant list.

### Phase 1 - Hunt (breadth, cheap)

Generate candidates by **differential reading**, not pattern-matching:

- **Sibling inconsistency**: route A checks X, sibling route B (list vs get, web vs
  CLI/API/MCP, sync vs async, create vs read, alias path vs canonical path) does not.
- **Identity mismatch**: the same resource keyed by two different principals in one
  flow (requester vs owner, sender vs creator, token org vs current org).
- **Lifecycle gaps**: revocation/removal/expiry not propagated (member removed but
  key/session/share still works; checked at create but not at read).
- **Fail-open defaults**: parsers or guards that `return nil`/allow on unrecognized
  input; deny-lists instead of allow-lists.
- **Trust-boundary crossings**: untrusted content (repo, document, web page,
  LLM output) reaching tools, shells, proxies, or credentials.
- Classic classes only where reachable: injection, SSRF, path traversal, unsafe
  deserialization, secrets in responses, IDOR/BOLA, missing tenant filter.

Parallelize by area with `Explore`/`general-purpose` subagents (one per subsystem).
Each returns at most 5 candidates as: claim, file:line, violated invariant,
attacker role, victim role, why reachable.

Drop immediately (see `references/gates.md` exclusion list): DoS/rate limits,
missing headers, self-only impact, secrets on disk, theoretical input validation,
anything needing admin or a disabled security control, anything confidence < 0.7.

Exit: a ranked candidate list (max ~8). Run the Phase 5 upstream search on the
top candidates now (tracker repo + target repo, exact route/function names,
`gh search issues/prs`). Candidates already filed or fixed upstream are dropped
as `duplicate-open <link>` / `fixed`: one line each, no hunt. Only novel
survivors (or user-requested repros for a static-only report) get picked to
prove, max 1-3.

### Phase 2 - Trace (depth, per candidate)

Before writing any test, read the whole path from the **real public entry point**
(router/route registration) to the sink:

1. Exact route + method + middleware actually mounted (check the router, not the
   handler alone). Confirm the attacker role can reach it with default config.
2. Every authz check on the path, and which principal each uses.
3. Where the claimed wrong value comes from (request, token, DB row) at each hop.
4. Whether the frontend/clients ever call it this way (affects frequency, not
   validity; direct API calls by an authed user are in scope).
5. Lifecycle facts that could kill the claim (resource torn down after each job,
   cache, feature flag off, feature unused in prod).
6. For any leaked secret/token/field: is it ever populated (`omitempty` + empty =
   no leak)? How does the server verify it, and is the verifying key actually set
   in deployed config? The answer can make the leak moot or reveal a bigger bug.

Rewrite the claim precisely: who (role) does what (request) to reach what (data
or action) that the model says they must not. Use the exact identities the code
uses (e.g. "resource creator vs request sender", not "owner vs user").

Exit: a precise claim with file:line for each hop, or the candidate is dropped.

### Phase 3 - Prove (Correctness gate)

Build the most faithful repro the environment allows, in this preference order:
real handler/service against local emulator > real code against local fake
upstream (fake-gcs, httptest capture) > staging with synthetic identities and
self-cleaning keys. Calling an internal helper directly only proves a primitive;
say so.

Required:
- **Attack case** reproduces N/N (N >= 5).
- **Control** with the same input that shows the guard works where it should
  (owner allowed, canonical path blocked, web route filters).
- **Fixed-build control** when cheap: apply the one-line fix, attack now fails.
- Canary values (unguessable strings) to prove the exact data crossed the boundary.
- Raw transcript saved (request, response, relevant bytes), secrets redacted.

Exit: N/N attack, passing control, transcript path. Otherwise `NEEDS EVIDENCE`.

### Phase 4 - Matter (Usefulness gate)

Answer every bug-or-not question in `references/gates.md`. Any "no" means the
label is not `bug` and it is not a security finding. Also state:
- Named attacker role and victim role; same-org vs cross-tenant; auth required?
- Concrete consequence demonstrated at the closest boundary, measured vs inferred.
- Preconditions and likely frequency; is the feature live and used?
- Severity with reasons for not one level higher and not one level lower.
- The fix a maintainer would ship, in one sentence, **and its reverse-direction
  risk** (does the obvious fix leak the other way?).

### Phase 5 - Upstream status

Search open/closed issues and PRs (`gh search issues/prs`, exact function names,
route, error strings, synonyms), recent commits touching the path, release notes.
Search **every repo where decisions live**, not just the target: the issue tracker
repo, PR bodies of the commits that last touched the path (`git log -L` / `gh pr
list --search <sha>`), and the infra/config repo. Merged PR bodies often record
"X deliberately keeps behavior Y"; that is a maintainer ruling.
Classify: `novel | duplicate-open | fixed | regression | documented-behavior |
discussed-no-ticket`. A finding fixed on main is not current. Record terms + date.

### Phase 6 - Falsify (independent review, mandatory)

Spawn a fresh `general-purpose` subagent (not a fork; it must not inherit your
reasoning). Give it ONLY: the precise claim, the pinned SHA, the repro path, and
`references/gates.md`. Instruct it to be read-only and to **try to break the claim**:
rerun the repro, check entry point, identities, lifecycle, config defaults,
whether test fixtures inflated any counts, whether the fix is safe, and whether
maintainers already ruled. It returns `ACCEPT | NEEDS EVIDENCE | REJECT` with
reasons per gate.

Fix every valid objection by re-running the relevant phase, never by rewording.

**Adjacent bigger issue found mid-trace:** do not swap it in silently. Report it
as a separate candidate, run it through Phase 5 first (it is often already
tracked), and only prove it if novel.
Then accept only if the reviewer and you both say ACCEPT.

### Phase 7 - Report

For each survivor, output (and draft the issue only if asked):

```
Title: [Security] <component>: <who> can <do what> <that the model forbids>
Label: bug | Severity: <level> (why not higher / lower) | Upstream: novel | SHA: <sha>
Claim: <one paragraph, exact identities>
Path: entry point -> ... -> sink (file:line each)
Evidence: N/N attack, control, fixed-build control, transcript path
Impact: measured vs inferred; preconditions; frequency
Not verified: <list>
Fix: <one sentence> + reverse-direction note
Falsification review: <verdict + objections resolved>
```

Also list rejected candidates in one line each with the gate they failed.
That list is useful signal, not failure.

## Running as a multi-agent workflow

If the user asked for a workflow/ultracode, run Phase 1 as parallel hunter agents
(one per subsystem), then pipeline each surviving candidate through
trace -> prove -> falsify agents, keeping under 10 agents. Otherwise do Phases
2-5 yourself and spawn only the Phase 6 falsifier.
