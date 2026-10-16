# 05: Device Certificate Revocation

**What to build:** An Organization Administrator revokes a Device Certificate, and when Intune retires, wipes or unenrolls a device, the platform's hourly poll of Intune's revocation queue revokes its certificate automatically; either way the serial is on the Issuing CA's CRL as soon as the Revocation commits.

**Blocked by:** 04, private-ca 06

**Status:** ready-for-human

- [x] Organization Administrators (`deviceCertificate.revoke`, to be added to the `deviceCertificate` resource in `server/src/permissions.ts`, which ticket 06 declared with `read` only) revoke with `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` or `privilegeWithdrawn`; the CRL is regenerated in the same Unit of Work.
- [x] The Intune revocation feed revokes the device's certificates with `cessationOfOperation`, recording the Enrollment Validator as actor, polling Intune's revocation queue at most hourly per Entra app (built per tenant, which is stricter: see Comments) and uploading a result for each request, as `docs/research/intune-scep-api.md` describes.
- [ ] Check against a real tenant whether the revocation API needs an Entra permission beyond `scep_challenge_provider` and `Application.Read.All`, and confirm how the service accepts `errorCode` (open questions in the research note).
- [x] `device_certificate.revoked` Audit Events for both.
- [x] Web: the revoke action on the Device Certificates list (`web/src/pages/device-certificates.tsx`, from ticket 06), offered with `deviceCertificate.revoke`.
- [x] Tests fetch the CRL and find the serial, after an administrator Revocation and after the Intune double queues one.

## Comments

Ticket 03 built the feed half: Device Certificate revocation columns, revoked Device Certificates on the Issuing CA CRL, the feed pass (`server/src/enrollment-validators.ts`) with `device_certificate.revoked` (validator as actor), and its CRL tests against the test kind. This ticket still adds the administrator route and the Intune feed. Note that 03 matches feed requests among the Device Certificates of the profiles sharing the feed, not the whole Organization's; revisit if that is wrong for Intune.

- Administrator half built while 04 was still open: `POST .../enrollment-profiles/{id}/device-certificates/{certificateId}/revocation` (`server/src/device-certificates.ts`) takes the Private CA reasons, locks the row as the feed pass does, revokes, audits `device_certificate.revoked` with the administrator as actor (no `detail.by`) and reissues the Issuing CA's CRL in one Unit of Work; 409 when already revoked, 502 (422) when the KMS does not answer (refuses) to sign the CRL. The feed then answers `already_revoked` and keeps the administrator's reason. The administrator's `device_certificate.revoked` and its CRL test are done; the feed's were done in 03 against the test kind. The Intune feed, its double and the real-tenant checks remain, and wait on 04's Intune kind.

- Intune half, once 04 merged: the `intune` kind has a revocation feed (`server/src/intune.ts`): `downloadRevocationRequests` (500 at most, no issuer filter) on the discovered PkiConnectorFEService, every request revoked with `cessationOfOperation`, and `uploadRevocationResults` once committed (`0` for revoked or already revoked, `4004` not found, `4100` for one the platform gave up on), thrown and told again unless Intune answers `{ "value": true }`. The feed is keyed by tenant, not Entra app: Intune's queue is the tenant's, so a request is matched among the Device Certificates of all the tenant's profiles, which settles the matching question above for Intune. The double (`server/test/intune-double.ts`) queues and hands over revocations and records results; the scenarios are in `server/test/intune-enrollment.test.ts`.
- Still open, needing a real tenant (the third box): whether revocation needs a permission beyond `scep_challenge_provider` and `Application.Read.All`, how the service takes `errorCode` (sent as the numeric string), the cool-down, the `issuerName` form, and whether a tenant's Entra apps share one queue. Recorded in `docs/research/intune-scep-api.md`.
