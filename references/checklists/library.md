# Library and package checklist

For code other programs import: parsers, serializers, archive and path
utilities, HTTP and URL libraries, auth and crypto libraries, SDKs, native
extensions. Standards: CWE Top 25 2025 (memory safety entries, CWE-22,
CWE-502, CWE-20), OWASP A03/A04/A08:2025.

**Threat model, written first.** The attacker controls data an application
passes to the library *through its documented, default API*. A bug needs: a
realistic caller, default or recommended options, and a consequence for that
caller. "A caller who passes untrusted input to an API documented as unsafe"
is documented behavior, not a finding. Self-impact on the attacker's own
process is excluded.

---

## LIB-01 Memory safety in parsers and codecs
Tier S · Yield medium with a sanitizer build, low without · Maps: CWE-787, CWE-125, CWE-416, CWE-190, CWE-122, CWE-121

**Applies:** C, C++, unsafe Rust, Go with `unsafe`/cgo, native extensions.

**Hunt**
- Size arithmetic before allocation (`len * n`, `a + b` without overflow
  checks), length fields read from input, signed/unsigned mixing.
- Unsafe string calls (`strcpy`, `strcat`, `sprintf`, `memcpy` with input
  lengths), especially behind many preconditions that fuzzers rarely reach.
- Algorithm edge cases: dictionary or table full, zero-length or maximal
  fields, recursion on nested input.
- Recently fixed overflows (CMN-01) and their siblings.

**Prove:** O-CRASH: an ASan/UBSan build, a testcase that crashes inside the
library's code (not the harness), N/N; then say whether it is a read, write or
UAF and how far the attacker controls it.
**Kill if:** the crash needs a caller to violate the documented contract;
a null dereference or assertion with no memory corruption is DoS (excluded).

---

## LIB-02 Deserialization and object construction
Tier S · Yield medium · Maps: CWE-502, CWE-1321, CWE-915

**Hunt**
- Default loaders that construct arbitrary types (YAML tags, pickle, Java/.NET
  polymorphic deserialization with type info, `Marshal`), "safe" modes and
  their bypasses.
- Prototype pollution in JS: deep merge, `set(obj, path, value)`, query-string
  and config parsers that accept `__proto__`, `constructor.prototype`.

**Prove:** O-DESER: a payload through the documented API produces a marker (code
execution) or, for pollution, `({}).polluted_<canary>` plus a real gadget in a
common consumer. Pollution without a gadget is B.
**Kill if:** only the unsafe opt-in API is affected and it is documented as such.
**Cases:** C02, C15.

---

## LIB-03 Archive, path and filesystem helpers
Tier S-A · Yield medium · Maps: CWE-22, CWE-59, CWE-367

**Hunt:** extraction of links, `..`, absolute paths, drive-relative paths on
Windows, case and Unicode collisions, races between check and write (raced
symlink creation), "safe join" helpers that check before resolving.

**Prove:** O-PATH write through the public API with default options.
**Cases:** C07, C16.

---

## LIB-04 Security controls that do not hold
Tier S · Yield high for security-focused libraries · Maps: CWE-693, CWE-347, CWE-79, CWE-918, CWE-208, CWE-436

**Hunt**
- Sanitizers (HTML, SVG, markdown): mutation XSS, namespace confusion,
  allowed-attribute abuse.
- Validators (URL, host, email, path containment, IP ranges) that a parser
  differential defeats (CMN-04).
- Verification APIs (JWT, SAML, signatures, HMAC, certificates) that return
  success on an error path, check one representation and return another, or
  accept attacker-chosen algorithms or keys.
- Constant-time comparison helpers that are not.

**Prove:** input that the control approves and that is dangerous in the
consumer it is documented to protect (a browser executes it, the verifier
accepts a forged token).
**Kill if:** the bypass needs non-default options documented as unsafe.
**Cases:** C04, C25.

---

## LIB-05 Unsafe defaults
Tier A · Yield medium · Maps: A02:2025 Security Misconfiguration, CWE-1188, CWE-276

Defaults that disable TLS verification, enable autoescape-off, allow all
origins, allow external entities, or follow redirects across hosts with
credentials. A finding only when the default is the common path and the docs
or type signatures imply safety; otherwise it is hardening.

---

## LIB-06 Native and FFI boundaries
Tier S · Yield low-medium · Maps: CWE-119, CWE-416, CWE-704

Lifetimes and lengths across FFI (`unsafe` blocks trusting C lengths, buffers
freed by one side and used by the other), `Send`/`Sync` implemented on types
that are not thread-safe, `transmute` of attacker-shaped data. Prove with a
sanitizer or Miri run on a testcase through the safe public API.
