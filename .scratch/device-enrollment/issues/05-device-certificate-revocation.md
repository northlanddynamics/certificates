# 05: Device Certificate Revocation

**What to build:** An Organization Administrator revokes a Device Certificate, and Intune's notices that a device was retired or wiped revoke its certificate automatically; either way the serial is on the Issuing CA's CRL at once.

**Blocked by:** 04, private-ca 06

**Status:** ready-for-agent

- [ ] Organization Administrators (`deviceCertificate.revoke`) revoke with `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` or `privilegeWithdrawn`; the CRL is regenerated in the same Unit of Work.
- [ ] The Intune revocation feed revokes the device's certificates with `cessationOfOperation`, recording the Enrollment Validator as actor, and reports back to Intune as the research note requires.
- [ ] `device_certificate.revoked` Audit Events for both.
- [ ] Tests fetch the CRL and find the serial, after an administrator Revocation and after the Intune double queues one.
