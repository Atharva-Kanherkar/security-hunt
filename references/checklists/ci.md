# CI/CD and supply-chain checklist

For repositories with GitHub Actions, GitLab CI, CircleCI, Buildkite, Azure
Pipelines, or publish/release automation. Standards: OWASP Top 10 2025 A03
(Software Supply Chain Failures) and A08, OWASP Top 10 CI/CD Security Risks,
CWE-94, CWE-829, CWE-1395.

**Threat model, written first.** The attacker is anyone who can open a pull
request from a fork, comment on an issue, create a branch name, or publish a
package the build depends on. The target is the repository's secrets, its
`GITHUB_TOKEN` write scope, its release artifacts, and cloud roles reachable
via OIDC. Never trigger a workflow on the real upstream to prove a finding:
reproduce in a scratch repository you own (O-CI).

---

## CI-01 Privileged trigger running untrusted code (pwn request)
Tier S · Yield high · Maps: CICD-SEC-4, CWE-94, CWE-829

**Hunt**
- Workflows on `pull_request_target`, `workflow_run`, `issue_comment`, or
  `pull_request_review` (privileged: secrets and a write token) that check out
  the PR head (`ref: ${{ github.event.pull_request.head.sha }}`, `head.ref`,
  `refs/pull/N/merge`) and then run anything that reads it: install scripts,
  builds, tests, linters with plugins, `make`, local actions (`uses: ./...`).
- `workflow_run` consumers downloading artifacts from the untrusted run and
  executing or unzipping them into sensitive paths.
- Label- or comment-gated workflows: who can add the label or comment? Is the
  checked-out SHA pinned to what the maintainer reviewed, or re-resolved later
  (TOCTOU between approval and checkout)?

**Prove:** O-CI: a scratch copy of the workflow plus a fork PR from a second
account (or `act` with the event payload) exfiltrates a canary secret or makes
a write with the token.
**Kill if:** no secrets and a read-only token in that job (`permissions:` block),
and no later privileged job consumes its outputs.
**Cases:** C19.

---

## CI-02 Expression injection in run steps and scripts
Tier S · Yield high · Maps: CICD-SEC-4, CWE-78, CWE-94

**Hunt**
- `${{ github.event.issue.title }}`, `.body`, `pull_request.title`, `.body`,
  `head_ref`, `comment.body`, `review.body`, `head_commit.message`, commit
  author names, `discussion.*`, branch names: interpolated directly in `run:`,
  in `actions/github-script` `script:`, or in inputs that a composite action
  places into a shell.
- The same in GitLab (`$CI_MERGE_REQUEST_TITLE` in scripts with eval) and
  other CI systems.

**Prove:** O-CI with a crafted title or branch name that runs a marker command
in the scratch repo.
**Kill if:** the value goes through an env var (`env: TITLE: ${{ ... }}` then
`"$TITLE"`) and is quoted; the workflow cannot be triggered by outsiders.
**Cases:** C19.

---

## CI-03 Mutable third-party references
Tier A (hardening unless a compromise is shown) · Yield n/a · Maps: CICD-SEC-3/8, CWE-829, CWE-1357

Third-party actions or orbs referenced by tag or branch instead of a commit
SHA; Docker images by tag; `curl | sh` installers from branches. This is a
hardening note: it becomes a finding only if a referenced tag is actually
compromised or the reference points at an account that no longer exists
(repo-jacking).

**Cases:** C18.

---

## CI-04 Over-broad tokens and cloud trust
Tier S · Yield medium · Maps: CICD-SEC-2/6, CWE-250, CWE-284

**Hunt**
- `permissions: write-all` or missing `permissions:` in workflows reachable by
  outsiders (default token scope depends on repo settings; check them).
- Cloud OIDC trust policies (AWS `sub` conditions, GCP workload identity,
  Azure federated credentials) with wildcards that let any branch, PR, or
  repository in the org assume a deploy role.
- Long-lived publish tokens (npm, PyPI, crates.io, Docker) stored as secrets
  where trusted publishing would bind them to a workflow.

**Prove:** from a PR-triggered scratch workflow, assume the role or use the
token for a write (in your own cloud account / scratch registry).
**Kill if:** the trust policy pins repo, ref and environment.

---

## CI-05 Cache and artifact poisoning across trust levels
Tier A-S · Yield medium · Maps: CICD-SEC-9, CWE-345, CWE-494

**Hunt:** caches written by PR or untrusted jobs and restored by release jobs
(same key prefix); build outputs passed between workflows without
verification; release jobs that run on caches created by `pull_request_target`.

**Prove:** in a scratch repo, an untrusted run writes a cache entry that a
privileged run restores and executes (marker).
**Kill if:** cache keys or scopes separate trust levels.

---

## CI-06 Self-hosted runners and runner reuse
Tier S · Yield medium · Maps: CICD-SEC-7, CWE-668

Self-hosted runners on public repositories, non-ephemeral runners shared
between trusted and untrusted jobs, runners with cloud credentials or network
access to internal systems. Prove only in your own scratch setup.

---

## CI-07 Package lifecycle and publish path
Tier A · Yield low-medium · Maps: A03:2025, CWE-506, CWE-829

`postinstall`/`prepare` scripts in dependencies executed in jobs holding
secrets; publish jobs that install dependencies with scripts enabled before
publishing; packages published from developer laptops. Mostly hardening;
a finding when a concrete path lets an outsider's code run with the publish
token.

**Cases:** C20.
