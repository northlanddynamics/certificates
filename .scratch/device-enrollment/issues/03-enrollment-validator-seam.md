# 03: Enrollment Validator seam and name rules

**What to build:** Enrollment Profiles name a pluggable Enrollment Validator that decides whether each request may be issued and is told the outcome, and profiles whose validator does not vouch for names enforce subject/SAN rules. The tracer's always-allow validator becomes a test-only kind of this seam. See `spec.md`, "Enrollment Validator seam" and "Name rules".

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] A validator kind registry like DNS Provider kinds, with `vouchesForNames`, `validate`, `issued`/`failed` notifications (at least once, retried in the background, never delaying the device's response), an optional revocation feed and `test`; credentials are Secrets given to it only when it runs.
- [ ] A refused request is answered FAILURE with a SCEP `failInfo` and writes an `enrollment.refused` Audit Event with the reason; nothing is issued.
- [ ] A profile whose validator does not vouch for names must carry subject/SAN rules (required attributes, allowed SAN types, patterns); requests that break them are refused. Tested with a test-only non-vouching kind.
- [ ] A contract test of the seam that later kinds reuse.
- [ ] `CONTEXT.md` gains Enrollment Validator.
