# <project> notes (template)

Copy to `references/<project>.md` and fill in. Keep it private if it names
unfixed bugs: this file should live only in your local install, never in a
public fork.

## Where bugs have been real

- Patterns that produced confirmed findings before (sibling route skipping the
  shared authz helper, revocation not propagated, fail-open parser, ...).
- Things that looked like bugs but were deliberate. Link the PR or ruling.

## Already tracked upstream (do not re-hunt unless asked)

- <short claim> -> <tracker link> (<status>, checked <date>)

## Where to search upstream (Phase 5)

- Issue tracker repo(s).
- Repos where decisions live: PR bodies, infra/config repo, deploy secrets layout.

## Repro environments

- Real handler against a local emulator: exact command, required env var names.
- Fake upstreams (httptest capture, fake object storage, ...).
- Staging rules: synthetic identities only, self-cleaning, metadata-only reads.
- Where scratch transcripts go (untracked).

## Known flakes (not evidence)

- <test name>

## Filing (only when asked)

- Tracker, labels, body language/format, who to assign or ping.
