# 05: Device Certificate Revocation

**What to build:** An Organization Administrator revokes a Device Certificate, and when Intune retires, wipes or unenrolls a device, the platform's hourly poll of Intune's revocation queue revokes its certificate automatically; either way the serial is on the Issuing CA's CRL as soon as the Revocation commits.

**Blocked by:** 04, private-ca 06

**Status:** ready-for-agent

- [ ] Organization Administrators (`deviceCertificate.revoke`) revoke with `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` or `privilegeWithdrawn`; the CRL is regenerated in the same Unit of Work.
- [ ] The Intune revocation feed revokes the device's certificates with `cessationOfOperation`, recording the Enrollment Validator as actor, polling Intune's revocation queue at most hourly per Entra app and uploading a result for each request, as `docs/research/intune-scep-api.md` describes.
- [ ] Check against a real tenant whether the revocation API needs an Entra permission beyond `scep_challenge_provider` and `Application.Read.All`, and confirm how the service accepts `errorCode` (open questions in the research note).
- [ ] `device_certificate.revoked` Audit Events for both.
- [ ] Tests fetch the CRL and find the serial, after an administrator Revocation and after the Intune double queues one.

## Comments

Ticket 03 built the feed half: Device Certificate revocation columns, revoked Device Certificates on the Issuing CA CRL, the feed pass (`server/src/enrollment-validators.ts`) with `device_certificate.revoked` (validator as actor), and its CRL tests against the test kind. This ticket still adds the administrator route and the Intune feed. Note that 03 matches feed requests among the Device Certificates of the profiles sharing the feed, not the whole Organization's; revisit if that is wrong for Intune.
