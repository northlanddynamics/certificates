# 04: Intune Enrollment Validator

**What to build:** An Organization Administrator connects an Enrollment Profile to their Intune tenant, and from then on only the requests Intune vouches for are issued, and Intune is told each outcome. Follows the research note from ticket 01.

**Blocked by:** 01, 03

**Status:** done

- [x] An Organization Administrator configures the Entra tenant ID, app ID and app secret (a Secret, never read back) and tests the connection (`enrollment_validator.tested`).
- [x] Each request is sent to Intune for validation; refused, failing or unreachable Intune answers FAILURE, with nothing issued.
- [x] Intune is told of success (thumbprint, serial, expiry, issuer) or failure, retried in the background.
- [x] The contract follows `docs/research/intune-scep-api.md`: Graph endpoint discovery, client credentials, a fixed provider name and version as `callerInfo`; the connection test gets both tokens and discovers both services, never calling validation or revocation. Before shipping, confirm the note's open questions on the Entra permissions (`scep_challenge_provider`, `Application.Read.All`) and the `IntuneDeviceId://` SAN.
- [x] The Intune kind vouches for names; Intune's device ID, read from the CSR's `IntuneDeviceId://` URI SAN when present (Intune's API never returns it), is stored on the Device Certificate.
- [x] An Intune double records validation requests and notifications and can refuse, fail or be unreachable; the seam's contract test runs against it.
- [x] The Enrollment Profiles page is shown in production once this kind is registered, with the Intune setup and test.

## Comments

Ticket 03 built the generic connection test route (`POST .../enrollment-profiles/{id}/validator/test`, `enrollment_validator.tested`) and the contract test (`server/test/enrollment-validator-contract.ts`); this ticket adds the Intune kind behind them, its double, and the setup UI.

- Ticket 06: the Intune kind should implement `deviceIdOf` (`server/src/enrollment-validator.ts`) from the `IntuneDeviceId://` URI SAN, so that its Device Certificates carry the device ID and can be found by it.

- Ticket 04 (done): the `intune` kind is `server/src/intune.ts`, its double `server/test/intune-double.ts` (a `fetch` answering as Entra, Graph and Intune), the contract and API-shape tests `server/test/intune-enrollment-validator.test.ts`, the scenarios `server/test/intune-enrollment.test.ts`. The permissions and the `IntuneDeviceId://` convention were confirmed from search excerpts (see the research note); `learn.microsoft.com` stayed unreachable. The seam's `test()` may now return a `note` (what it could not prove), shown by the test route. The refusal reason is Intune's code alone.
- For ticket 05: `issuingCertificateAuthority` is sent as @peculiar/x509 renders the Issuing CA's subject (`CN=…, O=…`, spaced). Matching a pulled request's `issuerName` already compares names structurally (`sameName` in `enrollment-validators.ts`), but check the form Intune gives back against a real tenant. The kind has no revocation feed yet; discovered `PkiConnectorFEService` is already kept for it. Discovered service URLs must be under `.manage.microsoft.com` (sovereign clouds would need more).
