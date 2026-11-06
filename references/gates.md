# The three gates (from kairo AGENTS.md, adapted for app security)

Any failed or incomplete gate blocks reporting. Decision:
`ACCEPT` all pass; `NEEDS EVIDENCE` may be valid, a gate lacks proof;
`REJECT` does not reproduce, wrong layer, already fixed, no consequence, or label is not `bug`.

## 1. Correctness

- Exact claim, not a nearby symptom. Exact repo, SHA, route, method, role, config.
- Real code through the real public entry point. Mock-only behavior is not proof.
- N/N repeated runs (N >= 5). Nondeterministic = lead, not finding.
- Control with the same meaningful input (guarded sibling route, owner caller,
  canonical path, fixed build, trigger removed).
- Canary strings to prove the exact data crossed.
- Rule out: stale version, non-default config, test fixtures, malformed input,
  mock artifacts, helper called directly instead of the real flow.
- Raw transcript saved, secrets redacted.

## 2. Usefulness (bug or not)

Answer all. Any "no" fails.

1. Is the expected behavior really the spec? Check code comments, sibling routes,
   tests, UI, and clients. A stale docstring is not the spec if the product
   intentionally behaves otherwise.
2. Have maintainers already ruled? Recent commit, PR body, comment, or deny-list
   that classifies it the other way -> `hardening` / `feature-request`, not `bug`.
   This includes a merged PR that names the behavior as a deliberate scoping
   choice, even if the question is still open on an issue. Then the finding is
   "reopen the decision", addressed to the owner, not a security bug.
3. Is the trigger supported usage? Default or recommended settings. A disabled
   security control, admin-only action, or misconfiguration is operator-misuse.
4. Is a real boundary crossed? Name the role the product says must not see/do it,
   then show that role seeing/doing it. Same role = nothing crossed.
5. What fix would a maintainer ship, in one sentence? If it is a doc edit or
   "don't do that", it is not a bug.

Exactly one label: `bug`, `docs-defect`, `hardening`, `feature-request`, `operator-misuse`.
Only `bug` is reported as a security finding. `hardening` may be mentioned as a
low-priority note only if the user wants it.

## 3. Upstream status

Search issues, PRs, commits, changelogs the same day with exact names + synonyms.
Classify `novel | duplicate-open | fixed | regression | documented-behavior |
discussed-no-ticket`. Unable to check = gate incomplete. Never guess.

## Hard exclusions (do not report)

Adapted from Anthropic's claude-code-security-review prompt and common bug bounty
N/A lists:

- DoS, resource exhaustion, rate limiting, CPU/memory use.
- Secrets stored on disk or in env (handled elsewhere) unless they leak to a
  lower-privileged caller over an API.
- Missing security headers, cookie flags, TLS config, banner/version disclosure.
- Self-only impact: self-XSS, self-DoS, user harming only their own data.
- Login/logout CSRF, clickjacking on non-sensitive pages.
- Lack of input validation without a proven exploit.
- Anything requiring admin/superadmin to harm themselves, or a disabled control.
- Theoretical issues in unreachable or dead code, tests, scripts, examples.
- Confidence below 0.7 after Phase 2.

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

## Sources

- kairo AGENTS.md (three gates, decision rule, independent reviewer)
- Anthropic claude-code-security-review: >80% exploitability confidence, hard
  exclusions, context research -> comparative analysis -> assessment
- "Sifting the Noise" (arXiv 2601.22952): agent FP filtering cuts noise heavily but
  aggressive filtering suppresses true positives; keep rejected candidates visible
- Hypothesis-validation multi-agent research: falsifiable checks instead of
  free-form justification reduce speculative reports
- Exploit validation via planted canary strings (Black Hat USA 2025, zero-FP offsec agents)
- OWASP API Security Top 10 API1 BOLA: compare responses across callers per object
