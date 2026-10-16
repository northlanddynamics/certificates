# 04: Intune Enrollment Validator

**What to build:** An Organization Administrator connects an Enrollment Profile to their Intune tenant, and from then on only the requests Intune vouches for are issued, and Intune is told each outcome. Follows the research note from ticket 01.

**Blocked by:** 01, 03

**Status:** ready-for-agent

- [ ] An Organization Administrator configures the Entra tenant ID, app ID and app secret (a Secret, never read back) and tests the connection (`enrollment_validator.tested`).
- [ ] Each request is sent to Intune for validation; refused, failing or unreachable Intune answers FAILURE, with nothing issued.
- [ ] Intune is told of success (thumbprint, serial, expiry, issuer) or failure, retried in the background.
- [ ] The contract follows `docs/research/intune-scep-api.md`: Graph endpoint discovery, client credentials, a fixed provider name and version as `callerInfo`; the connection test gets both tokens and discovers both services, never calling validation or revocation. Before shipping, confirm the note's open questions on the Entra permissions (`scep_challenge_provider`, `Application.Read.All`) and the `IntuneDeviceId://` SAN.
- [ ] The Intune kind vouches for names; Intune's device ID, read from the CSR's `IntuneDeviceId://` URI SAN when present (Intune's API never returns it), is stored on the Device Certificate.
- [ ] An Intune double records validation requests and notifications and can refuse, fail or be unreachable; the seam's contract test runs against it.
- [ ] The Enrollment Profiles page is shown in production once this kind is registered, with the Intune setup and test.

## Comments

Ticket 03 built the generic connection test route (`POST .../enrollment-profiles/{id}/validator/test`, `enrollment_validator.tested`) and the contract test (`server/test/enrollment-validator-contract.ts`); this ticket adds the Intune kind behind them, its double, and the setup UI.
