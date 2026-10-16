# 03: Enrollment Validator seam and name rules

**What to build:** Enrollment Profiles name a pluggable Enrollment Validator that decides whether each request may be issued and is told the outcome, and profiles whose validator does not vouch for names enforce subject/SAN rules. The tracer's always-allow validator becomes a test-only kind of this seam. See `spec.md`, "Enrollment Validator seam" and "Name rules".

**Blocked by:** 02

**Status:** done

- [x] A validator kind registry like DNS Provider kinds, with `vouchesForNames`, `validate`, `issued`/`failed` notifications (at least once, retried in the background, never delaying the device's response), an optional revocation feed (which revokes by serial and issuer and reports each outcome back to the kind) and `test`; credentials are Secrets given to it only when it runs.
- [x] A refused request is answered FAILURE with a SCEP `failInfo` and writes an `enrollment.refused` Audit Event with the reason; nothing is issued.
- [x] A profile whose validator does not vouch for names must carry subject/SAN rules (required attributes, allowed SAN types, patterns); requests that break them are refused. Tested with a test-only non-vouching kind.
- [x] A contract test of the seam that later kinds reuse.
- [x] `CONTEXT.md` gains Enrollment Validator.

## Comments

Done. The seam is `server/src/enrollment-validator.ts`: a kind declares its `settings` and optional `secret` (zod), `vouchesForNames`, an optional `revocationFeed` (`intervalMs`, and `sourceOf(settings)` so that profiles sharing a source, such as one Entra app, share one feed), and `create(settings, secret)`, which makes a validator with `validate`, `issued`, `failed`, `test` and optional `revocations.pull`/`report`. The production registry is `enrollment-validator-kinds.ts` (empty until ticket 04); the harness gives the app `test_allow`, `test_names` (does not vouch) and `test_double` (backed by `server/test/enrollment-validator-double.ts`, with a secret and a feed).

- Running validators is `server/src/enrollment-validators.ts`. `issued`, `failed` and feed reports go through an outbox (`enrollment_validator_message`) queued on the transaction of what they tell of and sent by a background pass (every 30s in `index.ts`), retried with backoff six times and then given up (`failed`). This cut-off, and the lack of any alert when a message is given up, is left for the notifications decision (ticket 09). `failed` is told only for requests the validator was asked about.
- Every refusal (key type, name rules, the Issuing CA, the validator, or issuance) is FAILURE `badRequest` with an `enrollment.refused` Audit Event.
- Name rules (`server/src/name-rules.ts`): required subject attributes, per-attribute patterns, allowed SAN types and per-type patterns. Patterns are wildcards (`*`) and case-insensitive, not regular expressions, so a device's input can never make an administrator's pattern slow. The rules are strict: a subject attribute or SAN type they don't name is refused. They're checked before the validator is asked.
- Validators throw `EnrollmentValidatorError` for anything about their service. Its message must never quote the secret, and the contract checks this. Any other error is treated as a bug: only its class name is shown, kept or logged, never its message.
- A request the validator allowed but the platform then fails to sign or store is answered FAILURE, written as `enrollment.refused`, and told to the validator as failed.
- What a feed hands over is stored (`enrollment_validator_revocation_request`) before it is acted on, because it is not handed over again. Stored requests are revoked by the next pass, retried up to five times, and then answered as failed. Profiles that share a feed may hold different secrets, so the feed is pulled and told with the first one that works.
- The feed pass (every minute) pulls each due feed, revokes matches by serial and issuer among the Device Certificates **of the profiles sharing that feed** (narrower than "the Organization's", so that one integration cannot revoke another's certificates), publishes the Issuing CA's CRL in the same Unit of Work, and queues the outcomes (`revoked`, `already_revoked`, `not_found`, or `failed` after five rolled-back tries). To make this work, this ticket adds Device Certificate revocation columns, and the Issuing CA CRL now lists revoked Device Certificates. Ticket 05 still adds the administrator revocation route and the Intune feed.
- `POST .../enrollment-profiles/{id}/validator/test` (`enrollmentProfile.update`) writes `enrollment_validator.tested`.
- The contract test is `server/test/enrollment-validator-contract.ts`, run against the test kind in `enrollment-validator-seam.test.ts`. Ticket 04 runs it against the Intune double.
- The web's API types follow the new response shape. No UI for settings, secrets or name rules yet: ticket 04 adds the Intune setup.
