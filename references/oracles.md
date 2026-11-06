# Proof oracles

An oracle is a check that a machine can decide: the canary arrived, the marker
file exists, the browser ran the function. Reasoning, however convincing, is
not an oracle. Ten agents once agreed unanimously on a padding oracle that did
not exist; one empirical test killed it (Refute-or-Promote).

Rules for every oracle:

- **Canaries are unguessable** (`zz_<16 random hex>`), created fresh per run,
  and planted by the *victim* side of the setup.
- **The target must produce the evidence, not the PoC.** Check the marker did
  not exist before the run; check which process (uid, pid, parent) created it;
  never let the PoC script write, print or echo the canary itself.
  (Refute-or-Promote: PoCs that detected their own artifacts were a real
  false-positive class.)
- **Attack N/N with N >= 5, control with the same shape of input.** For
  inherently racy or model-driven paths, report k/N and separate the
  deterministic part (see O-RACE, O-AGENT).
- **Local and scratch only.** Listeners on loopback, fake upstreams, scratch
  repos and accounts you own. No public interaction services with real data,
  no production CDNs, no real upstream CI.
- **Save the transcript**: commands, requests, responses, the bytes that prove
  the crossing. Redact secrets; keep canaries.

---

## O-AUTHZ (access control: BOLA, BFLA, tenant, lifecycle)
1. Create attacker A and victim V with the roles and tenants the claim names.
   Confirm identities with a whoami call for each token.
2. V creates the object with a canary in a field A must not see.
3. Obtain the object id the way A realistically could (listed somewhere A can
   see, guessable, leaked in a URL). If A cannot get the id, say so; it changes
   severity and may kill the claim.
4. A calls the exact public route. Success: V's canary in A's response, or V's
   object changed (read it back as V).
5. Controls: A on A's own object succeeds; A on V's object via the guarded
   sibling is denied; after the one-line fix, the attack is denied.

## O-AUTHN (identity, tokens, sessions, SSO)
Success is a whoami (or equivalent) that returns V while the attacker only used
attacker-held material: a forged or replayed token, an IdP identity the
attacker controls, a reset link they received. Control: the same flow with an
honest token for A returns A.

## O-XSS
A headless browser (Playwright) logged in as the victim loads the page. The
payload calls a fresh function name, e.g. `window.zz_ab12cd()`, defined nowhere
else; success is that call observed via an exposed binding or console event.
Use the deployed CSP header. Reflected or stored text in the HTML is not proof.
Control: the same payload in an escaped context renders as text.

## O-CSRF / O-CORS
A page served from a different origin, loaded in a headless browser with the
victim's real cookies, performs the action (CSRF) or reads a victim canary
(CORS). Record the cookie attributes and the response headers.

## O-SSRF
Start a listener on a loopback or private address with a random path
(`python3 -m http.server` or `nc -l`). Success: the target's server process
requests `/<canary>`. For impact, run a fake metadata or internal service that
returns a second canary and show it in the attacker's response. Blind with no
observable response and no side effect: `NEEDS EVIDENCE`. Control: an allowed
public-style URL takes the normal path; the blocked address is rejected on the
guarded sibling.

## O-CMDI (command and argument injection)
The payload makes the target run `touch /tmp/zz_<canary>` (or the platform
equivalent). Success: the file exists after, did not exist before, and its
owner is the target process's user. Control: a benign value of the same shape
creates nothing. Never use payloads that touch anything outside a scratch path.

## O-CONFIG-EXEC (repo-controlled config, agent and CLI startup)
A scratch repository contains the malicious config (hook, MCP server, `.env`,
plugin) whose command creates the marker. Fresh clone into a new directory,
run the tool with default flags and default user settings in a clean HOME.
Success: marker created before any trust prompt, or without one. Record the
exact prompts shown (screenshot or terminal capture). Control: decline the
prompt if there is one; no marker.

## O-PATH (traversal, archive extraction, arbitrary read/write)
Read: plant `zz_<canary>.txt` outside the allowed root (in a scratch dir) and
retrieve its content through the target. Write: the target writes a file
containing a canary to a path outside the extraction or upload root, inside a
scratch dir you created. Control: a benign archive or path stays inside.

## O-DESER
The crafted payload makes the target create the marker file (code execution)
or call a function with an observable side effect. For prototype pollution,
show `({}).zz_<canary>` set in the target process **and** a gadget that turns
it into a security effect; pollution alone is a B lead.

## O-SQLI / O-SSTI
Prefer data extraction: read a canary row the attacker must not see, or
evaluate an expression whose result could only come from the engine (e.g.
`{{ 7*'7' }}` style probes, then a canary-bearing expression). Boolean or
error differentials need N/N plus a control. Timing alone is `NEEDS EVIDENCE`.

## O-RACE
Send the racing requests in one burst (HTTP/2 single-packet, or parallel
connections released together). Success: the limited effect exceeds its limit
(two redemptions of a single-use code) in k of N bursts, with the canary
resource. Control: the same requests sent sequentially never exceed the limit.
Report k/N; a race that never reproduces is a lead, not a finding.

## O-LOCALHOST (local services from a web page)
Serve a page from a different local origin (`python3 -m http.server 8999`)
that sends the request to the service in a headless browser; success is a
state change or a canary read. For DNS rebinding, show the service accepts
`Host: attacker.test` (curl is enough for this half) and that no secret token
blocks it. Control: the request with a correct token works; a wrong `Origin`
is rejected on the guarded route.

## O-AGENT (prompt injection to action)
Two parts, reported separately:
1. **Deterministic gate check.** Show the dangerous tool call executes without
   an approval when issued in this context (call the tool path directly, or
   replay a recorded tool call). This is the bug, and it is N/N.
2. **Model compliance rate.** A fixture with injected instructions (a local
   web page, issue, or document; never a real third-party resource) asks the
   agent to send a private canary to a loopback listener. Run N >= 5 sessions
   with the product's default model and prompt; report k/N.
Control: with the gate enabled (or the untrusted source removed), no request
reaches the listener.

## O-CI
Copy the workflow into a scratch repository you own with a canary secret.
Trigger it as an outsider would (a fork PR from a second account, an issue
comment, or `act` with a recorded event payload). Success: the canary secret
reaches a listener you control or the token performs a write in the scratch
repo. Never open PRs or comments on the real upstream to test.

## O-CRASH (memory safety)
Build with AddressSanitizer/UBSan (or Miri for Rust). Success: the testcase
crashes N/N with a report whose top frames are in the target's code, not the
harness. State the bug type (read, write, UAF) and how much of it the input
controls. A crash without memory corruption is DoS (excluded).

## O-OPEN (OS URL/file handler)
Use a scheme or path whose handler creates the marker (a local test app or a
`file:` path to a script in a scratch dir, on a disposable VM or account if the
handler would launch anything real). Show the URL arrived from the untrusted
source. Control: an `https:` URL opens the browser only.
