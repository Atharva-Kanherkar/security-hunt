# The three gates (from kairo AGENTS.md, adapted for app security)

Any failed or incomplete gate blocks reporting. Decision:
`ACCEPT` all pass; `NEEDS EVIDENCE` may be valid, a gate lacks proof;
`REJECT` does not reproduce, wrong layer, already fixed, no consequence, or label is not `bug`.

## 1. Correctness

- Exact claim, not a nearby symptom. Exact repo, SHA, route, method, role, config.
- The claim matches the evidence. Agents often prove a *different* issue than
  the one they set out to prove (a stack trace instead of the weak crypto they
  claimed). Re-read the claim after the repro and rewrite it to what was shown.
- Real code through the real public entry point. Mock-only behavior is not proof.
- N/N repeated runs (N >= 5). For races and model-driven paths, report k/N and
  prove the deterministic part (the missing lock, the missing approval gate)
  N/N on its own. A result that never repeats is a lead, not a finding.
- Control with the same meaningful input (guarded sibling route, owner caller,
  canonical path, fixed build, trigger removed).
- Canary strings to prove the exact data crossed, produced by the target, not
  by the PoC. Check that markers did not exist before the run and were created
  by the target's process.
- Rule out: stale version, non-default config, test fixtures, malformed input,
  mock artifacts, helper called directly instead of the real flow.
- Every `file:line` in the report resolves at the pinned SHA and says what the
  report claims (`scripts/check-citations.sh report.md <sha>`).
- Raw transcript saved, secrets redacted.

## 2. Usefulness (bug or not)

Answer all. Any "no" fails.

1. Is the expected behavior really the spec? Check code comments, sibling routes,
   tests, UI, and clients. A stale docstring is not the spec if the product
   intentionally behaves otherwise. **Intended functionality is not a bug**: a
   CLI that runs the commands its user typed, a shell MCP server that runs
   shell, an admin console that lets admins administer.
2. Have maintainers already ruled? Recent commit, PR body, comment, or deny-list
   that classifies it the other way -> `hardening` / `feature-request`, not `bug`.
   This includes a merged PR that names the behavior as a deliberate scoping
   choice, even if the question is still open on an issue. Then the finding is
   "reopen the decision", addressed to the owner, not a security bug.
3. Is the trigger supported usage? Default or recommended settings. A disabled
   security control, admin-only action, or misconfiguration is operator-misuse.
   Scenarios that start from stolen credentials or an already-compromised host
   are out of scope.
4. Is a real boundary crossed? Name the role the product says must not see/do it,
   then show that role seeing/doing it. Same role = nothing crossed. Platform
   protections count: same-origin policy, SameSite cookies, CSP, sandboxing
   and egress rules in the deployed config can each make the crossing impossible.
5. What fix would a maintainer ship, in one sentence? If it is a doc edit or
   "don't do that", it is not a bug.

Exactly one label: `bug`, `docs-defect`, `hardening`, `feature-request`, `operator-misuse`.
Only `bug` is reported as a security finding. `hardening` may be mentioned as a
low-priority note only if the user wants it. A violated guideline (a missing
header, an unpinned action, a weak default) is `hardening` until an exploit is
shown.

## 3. Upstream status

Search issues, PRs, commits, changelogs the same day with exact names + synonyms.
Classify `novel | duplicate-open | fixed | regression | documented-behavior |
discussed-no-ticket`. Unable to check = gate incomplete. Never guess.

## Independent review (Phase 7) rules

These come from multi-agent false-positive research (Refute-or-Promote,
Sifting the Noise, GitHub Security Lab taskflows). Follow them literally.

- **Cold start.** The falsifier gets the claim, SHA, repro path and this file.
  Not your reasoning, not your confidence, not the hunt history. Fresh-context
  review beats same-session review.
- **Kill mandate.** Its job is to reject. It is not asked to "improve" or
  "discuss" the claim. Debate rounds degrade quality through persuasion; do not
  run them.
- **One candidate per reviewer.** Batched reviews skip steps.
- **Empirical beats argument.** If the falsifier can rerun the repro, it must.
  A reasoned objection is resolved by a new run, never by rewording.
- **Unanimity is weak evidence.** Agents from one model family share training
  priors and make the same mistakes together. When a second model family is
  available and the user allows sending the code to it (for example the
  `codex` CLI), use it as an additional cold reviewer for anything rated High
  or above.
- **Recalibrate severity downward first.** Adversarial reviewers lowered the
  CVSS of 8 of 9 confirmed findings in one study. Argue for the lower level and
  only keep the higher one if it survives.
- **Deterministic checks go to tools, not judgment.** Versions from lockfiles,
  routes from the router, config from the deployed files, citations from
  `check-citations.sh`.

## Do not over-filter

Filtering also kills real bugs. The best agent setup in Sifting the Noise still
discarded 22% of true positives, and over half in crypto (CWE-327/328),
trust-boundary (CWE-501) and cookie (CWE-614) classes. In Refute-or-Promote, a real
lcms2 integer overflow was unanimously killed by agents and saved by a human.

- A candidate you cannot prove is `NEEDS EVIDENCE`, listed with what is
  missing. It is not deleted.
- Every `REJECT` names the gate and the evidence. "Seems unlikely" is not a reason.
- The user can override any verdict; record their decision.

## Hard exclusions (do not report)

Adapted from Anthropic's claude-code-security-review prompt and common bug bounty
N/A lists:

- DoS, resource exhaustion, rate limiting, CPU/memory use, ReDoS. Exception:
  when the target's own security policy or its past advisories treat resource
  exhaustion as a vulnerability (common for parser and archive libraries), it
  may be reported, labeled DoS, and ranked no higher than B.
- Secrets stored on disk or in env (handled elsewhere) unless they leak to a
  lower-privileged caller over an API.
- Missing security headers, cookie flags, TLS config, banner/version disclosure.
- Self-only impact: self-XSS, self-DoS, user harming only their own data.
- Login/logout CSRF, clickjacking on non-sensitive pages.
- Lack of input validation without a proven exploit.
- Anything requiring admin/superadmin to harm themselves, or a disabled control.
- Theoretical issues in unreachable or dead code, tests, scripts, examples.
- For LLM apps: jailbreaks, harmful output, hallucinations, system prompt
  disclosure when it holds no secrets, token-cost abuse.
- A dependency version match without a reachable vulnerable path.
- Confidence below 0.7 after Phase 3 (trace).

Confidence scale: 0.9-1.0 exploit path executed; 0.8-0.9 clear pattern, traced
end to end; 0.7-0.8 needs specific conditions (state them). Below 0.7: drop.

## Lessons from past false-positive near misses

These were caught only by independent review. Check each before reporting.

- **Wrong entry point.** The obvious UI action did not trigger the mismatch; only a
  follow-up path did. Trace the actual mount, not the likely one.
- **Wrong identity names.** The claim named roles the code never compares.
  Use the exact principals the code checks; the direction of impact can flip.
- **Lifecycle kills the claim.** A resource claimed to persist is torn down by
  cleanup code (`finally`, defers, TTLs). Read cleanup paths before claiming persistence.
- **Inflated counts.** Affected-object counts included test fixtures.
  Count only real entries and say which were excluded. Read metadata, never contents.
- **Primitive vs flow.** Calling an internal helper directly proves the primitive,
  not the authenticated end-to-end flow. Say which one you proved.
- **Unsafe fix.** The obvious fix can leak data the other way.
  Always evaluate the fix's reverse direction.
- **Feature status.** A maintainer may remove an unused feature rather
  than fix it. Check whether the feature is live and used; it changes the fix and
  severity, not validity.
- **Already decided.** Behavior can reproduce cleanly and still be a
  recorded maintainer decision. Read the PR that last touched the path before
  calling it a bug.
- **Frontend hides it.** A route the UI never calls this way is still in scope for
  an authed user via direct API, but lowers frequency. Say so.
- **Name-level pattern matching.** An API called `format()` or `render()` was
  reported as XSS; it escaped its input. Read what the sink does.
- **Missed auth layer.** GitHub Security Lab's rejected findings were mostly a
  browser mitigation or an auth layer the agent had not read, not invented
  code. Look for gateways, middleware and platform defaults before claiming.
- **Self-contaminated PoC.** A PoC detected the artifact it had planted itself.
  The target must produce the evidence.
- **Consensus on a ghost.** Many agents agreed on a padding oracle that did not
  exist; one test killed it. Agreement is not evidence.

Sources for these rules are in `sources.md`.
