---
name: security-hunt
description: Find real, verified security bugs in a codebase with no false positives. Fingerprints the target's stack (web, API, CLI, desktop/localhost, LLM agent/MCP, library, CI), loads checklists built from OWASP Top 10 2025, OWASP API/LLM/Agentic Top 10, ASVS 5.0, CWE Top 25 2025 and real CVE write-ups, ranks the items by likely impact, hunts them in order, proves each candidate with a deterministic oracle and a control, has a cold independent agent try to kill it, and reports only the top survivors. Use when asked to "find security issues", "security hunt", "bug hunt", "kairo hunt", "audit this repo for vulns", "pentest this code", "find a real security bug", or to verify/triage a suspected vulnerability or someone else's security finding.
---

# security-hunt

Goal: every finding this skill reports is **real, reachable, reproduced, and matters**.
Zero findings is an acceptable, honest result. A wrong finding is worse than none:
it costs maintainer trust and the next real report gets ignored.

The model is a candidate generator, never the authority. A candidate becomes a
finding only after execution evidence plus an independent falsification attempt.

## Files

| File | Read it |
| --- | --- |
| `scripts/fingerprint.sh` | Run in Phase 0. Detects profiles, hot sinks, tenant signals, CI triggers, past security commits. Calls `gh api` once for advisories unless `--offline` |
| `references/ranking.md` | Phase 1. Scoring and default order per profile |
| `references/checklists/common.md` | Always. Variants, skipped invariants, fail-open, parser differentials, sinks |
| `references/checklists/{web,api,cli,desktop,agent,library,ci}.md` | Phase 1, only the profiles that apply |
| `references/oracles.md` | Phase 4. How to prove each class, and what is not proof |
| `references/cases.md` | When an item cites `Cnn`, or to seed variant analysis |
| `references/gates.md` | Phase 2 (exclusion list), again before Phase 4, and give it to the falsifier |
| `references/projects/<project>.md` | If it exists for the target: past bugs, tracked issues, repro setup |
| `scripts/check-citations.sh` | Phase 8, before anything is shown as a finding |

## Hard rules

- **Authorized targets only.** Your own repos/worktrees, local emulators, fake
  upstreams, scratch repos and accounts, and staging with synthetic identities.
  Never prod data, never real user content, never another tenant, never a live
  destructive action (no real commit/merge/delete/payment to "prove" impact;
  trace the last hop instead). Never trigger the real upstream's CI.
- Never print, copy, or persist a credential. Env var names only.
- Work on a pinned commit of the latest default branch (`git fetch` then a detached
  worktree). Record the SHA. Findings on stale code are invalid. If you cannot
  fetch (offline, shallow clone, a checkout the user chose), use what you have
  and say in the report that it may be stale.
- **Check upstream before you trace or prove a candidate.** Run the Phase 6
  search on each candidate as soon as it exists. Already filed, fixed, or ruled
  on: record the link and status in one line and move on, unless the user asked
  for a repro of an existing static-only report. If you cannot search (offline),
  mark it `upstream: not checked`; the upstream gate is then incomplete and the
  candidate can be at most `NEEDS EVIDENCE`.
- Repro tests are scratch: name them `zz_*_repro_test.*`, never commit them.
- Do not file, comment, label, or message anyone without the user's explicit ask.
  Hand over drafts.
- Plain language. State what was NOT verified.

## Workflow

Track progress with a task list. Each phase has an exit criterion; do not skip.

### Phase 0 - Scope and fingerprint

1. Pin the target: repo, SHA, date. Fetch the latest default branch.
2. Run `scripts/fingerprint.sh <repo>`. Read its output as hints: confirm each
   profile by opening the files it cites. Drop profiles whose evidence is a side
   project (a marketing site, examples, a benchmark dir) unless it is in scope;
   add profiles it missed. A target can have several (a desktop app with a local
   daemon and an agent is `desktop + cli + agent`).
3. Write the security model in 5 lines: principals and tenants, roles, who may
   see/do what, trust boundaries (user to API, web page to localhost, repo to
   tool, untrusted text to agent, PR to CI, service to service). Source it from
   code (authz helpers, middleware, policy) and docs, not assumptions.
4. List the **intended invariants** the code itself states: guard helpers used
   everywhere, comments like "only the owner may delete", deny-lists, approval
   gates, recent hardening commits. The best bugs
   are places that skip an invariant the codebase enforces elsewhere.
5. Read the project's own security policy: `SECURITY.md`, security sections of
   the README or docs, threat-model docs, past advisories. Record what it rules
   out of scope (e.g. "callers must filter link entries", "an attacker who
   controls the destination folder is out of scope") as kill-checks, and what
   it rules in (some parser libraries treat resource exhaustion as a
   vulnerability; see the DoS note in `gates.md`).

Exit: fingerprint output, confirmed profiles, the model, the invariant list,
the project's in/out-of-scope list.

### Phase 1 - Plan

1. Load `common.md` plus the checklist for each confirmed profile (`web`
   always brings `api`). Do not load the others.
2. For every item, decide `applies` (cite the file or fingerprint line) or
   `n/a` (one-line reason). Items whose trigger needs admin or a disabled
   control are `n/a` by the gates.
3. Score the applicable items with `ranking.md`
   (Impact + Exposure + Yield + Signal) and sort. `CMN-01` (variants of past
   security fixes) and `CMN-02` (skipped invariants) go first whenever they apply.
4. Write the plan table from `ranking.md`. Budget: the top 8 to 12 items. The
   rest are `not run`, and the report says so.

Exit: the ranked plan table.

### Phase 2 - Hunt (in plan order)

For each item: follow its **Hunt** steps against this codebase, read the code
the greps land on, and stop the item when it is clean or yields candidates.
Update the plan table as you go. The **Prove** lines name oracles (`O-AUTHZ`,
`O-AGENT`, ...) defined in `oracles.md`; you need them from Phase 4.

Write each candidate as a falsifiable hypothesis:

```
C<n> [ITEM-ID] <attacker role> can <do what> to <victim role/data> via <entry point>
   because <the missing or wrong check>
   path: <entry file:line> -> ... -> <check or sink file:line>
   kill-check: <the one fact that would make this false, and where to look>
   score: <I+E+Y+S>, confidence <0.x>
```

Naming the kill-check up front is the point: look for it before anything else.
Drop on sight anything in the gates.md exclusion list, anything the project's
policy rules out (Phase 0 step 5), or below confidence 0.7.

Stop hunting when the budgeted items are done or you hold 8 candidates. On a
heavily audited target (many advisories, a long run of recent hardening),
expect few or no findings; spend the budget on bypasses of the latest fixes
and report clean coverage honestly rather than stretching for a finding.

Then run the Phase 6 upstream search on each candidate. Already tracked or
fixed: one line, dropped. Pick the top 1 to 3 novel candidates by score to take
further; the rest stay listed as leads.

Parallelize by profile or item group with `Explore`/`general-purpose`
subagents when the plan is large. Each returns at most 5 candidates in the
format above and must not spawn its own subagents.

Exit: candidates, each with an upstream status.

### Phase 3 - Trace (depth, per candidate)

Before writing any test, read the whole path from the **real public entry point**
(router/route registration, CLI arg parser, IPC registration, MCP tool table,
workflow trigger) to the sink:

1. Exact route/command/tool + the middleware or guards actually mounted (check
   the registration, not the handler alone). Confirm the attacker role reaches
   it with default config.
2. Every authz check on the path, and which principal each uses.
3. Where the claimed wrong value comes from (request, token, DB row, repo file,
   server response, model output) at each hop.
4. Whether clients ever call it this way (affects frequency, not validity; a
   direct API call by an authed user is in scope).
5. Lifecycle facts that could kill the claim (resource torn down after each job,
   cache, feature flag off, feature unused in prod).
6. For any leaked secret/token/field: is it ever populated (`omitempty` + empty =
   no leak)? How does the server verify it, and is the verifying key set in
   deployed config? The answer can make the leak moot or reveal a bigger bug.
7. Answer the kill-check.

Rewrite the claim precisely with the identities the code uses (e.g. "resource
creator vs request sender", not "owner vs user").

Exit: a precise claim with file:line for each hop, or the candidate is dropped.

### Phase 4 - Prove (Correctness gate)

Read `gates.md`, then use the oracle the item names in `oracles.md`. Build the
most faithful repro the environment allows: real handler/service against a
local emulator > real code against a local fake upstream > staging with
synthetic identities and self-cleaning keys. Calling an internal helper
directly proves only a primitive; say so.

Required:
- **Attack case** reproduces N/N (N >= 5). Races and model-driven paths: k/N
  plus the deterministic part N/N (see O-RACE, O-AGENT).
- **Control** with the same input shape that shows the guard works where it
  should (owner allowed, canonical path blocked, guarded sibling denies).
- **Fixed-build control** when cheap: apply the one-line fix, attack now fails.
- Canary values produced by the target, not the PoC.
- Raw transcript saved (request, response, relevant bytes), secrets redacted.

Exit: N/N attack, passing control, transcript path. Otherwise `NEEDS EVIDENCE`.

### Phase 5 - Matter (Usefulness gate)

Answer every bug-or-not question in `gates.md`. Any "no" means the label is
not `bug` and it is not a security finding. Also state:
- Named attacker role and victim role; same-org vs cross-tenant; auth required?
- Concrete consequence demonstrated at the closest boundary, measured vs inferred.
- Preconditions and likely frequency; is the feature live and used?
- Severity with reasons for not one level higher and not one level lower.
  Argue for the lower level first.
- The fix a maintainer would ship, in one sentence, **and its reverse-direction
  risk** (does the obvious fix leak the other way?).

### Phase 6 - Upstream status

Search open/closed issues and PRs (`gh search issues/prs`, exact function names,
route, error strings, synonyms), recent commits touching the path, release notes,
published advisories. Search **every repo where decisions live**: the issue
tracker repo, PR bodies of the commits that last touched the path (`git log -L` /
`gh pr list --search <sha>`), and the infra/config repo. Merged PR bodies often
record "X deliberately keeps behavior Y"; that is a maintainer ruling.
Classify: `novel | duplicate-open | fixed | regression | documented-behavior |
discussed-no-ticket`. A finding fixed on main is not current. Record terms + date.

### Phase 7 - Falsify (independent review, mandatory)

For **each** candidate that passed Phases 4 to 6, spawn a fresh
`general-purpose` subagent (not a fork; it must not inherit your reasoning).
Give it ONLY: the precise claim, the pinned SHA, the repro path, and
`references/gates.md`. Instruct it:

> Read-only. Your job is to make this claim fail. Rerun the repro. Check the
> entry point, the identities, lifecycle, deployed config defaults, auth layers
> and platform protections the claim may have missed, whether fixtures inflated
> anything, whether the evidence was produced by the target or the PoC, whether
> the claim matches what the evidence shows, whether maintainers already ruled,
> and whether the fix is safe in reverse. Argue for the lowest defensible
> severity. Return ACCEPT, NEEDS EVIDENCE, or REJECT with reasons per gate.
> Do not spawn subagents.

Follow the review rules in `gates.md`: one candidate per reviewer, no debate
rounds, empirical reruns over arguments, a second model family as an extra cold
reviewer for High/Critical when available and allowed.

Fix every valid objection by re-running the relevant phase, never by rewording.
Accept only if the reviewer and you both say ACCEPT.

**Adjacent bigger issue found mid-trace:** do not swap it in silently. Add it
as a new candidate, run Phase 6 on it first (it is often already tracked), and
only prove it if novel.

### Phase 8 - Report

1. Write the report, then run
   `scripts/check-citations.sh <report.md> <sha> <repo>`. Any MISSING or RANGE
   line, or a printed line that does not say what the report claims, is fixed
   before the report is shown.
2. Lead with the **top findings**: at most 5 accepted survivors, ranked by
   severity then confidence. Each one:

```
Title: [Security] <component>: <who> can <do what> <that the model forbids>
Label: bug | Severity: <level> (why not higher / lower) | Upstream: novel | SHA: <sha>
Item: <ITEM-ID> | Maps: <OWASP / CWE ids from the item>
Claim: <one paragraph, exact identities>
Path: entry point -> ... -> sink (file:line each)
Evidence: N/N attack, control, fixed-build control, transcript path
Impact: measured vs inferred; preconditions; frequency
Not verified: <list>
Fix: <one sentence> + reverse-direction note
Falsification review: <verdict + objections resolved>
```

3. Then, briefly:
   - **Coverage:** the plan table with final status per item (`clean`,
     `candidate`, `n/a`, `not run`). This is what tells the user how much was
     actually looked at.
   - **Needs evidence:** candidates that may be real, each with what is missing.
   - **Rejected:** one line each with the gate it failed. Useful signal, not failure.
   - **Hardening notes:** only if the user wants them.

Draft issues only if asked.

## Running as a multi-agent workflow

If the user asked for a workflow or ultracode: Phase 2 hunters run in parallel
(one per profile or item group from the plan), then each surviving candidate
pipelines through trace -> prove -> falsify agents. Keep under 10 agents, and
tell every agent not to spawn its own. Otherwise do Phases 3 to 6 yourself and
spawn only the Phase 7 falsifiers.
