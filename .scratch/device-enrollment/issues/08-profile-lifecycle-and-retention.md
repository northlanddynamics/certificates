# 08: Profile lifecycle and retention

**What to build:** An Organization Administrator disables a profile, rotates its RA certificate, and moves it to a new Issuing CA when the old one is retired; expired Device Certificates are pruned after the Organization's retention period.

**Blocked by:** 02, private-ca 09

**Status:** ready-for-agent

- [ ] Disabling a profile refuses all enrollment and keeps its Device Certificates and CRL entries (`enrollment_profile.disabled`).
- [ ] A profile whose Issuing CA is retired refuses enrollment until it is pointed at an active one (`enrollment_profile.updated`).
- [ ] RA rotation issues a new RA certificate and key, served by `GetCACert` from then on (`enrollment_profile.ra_rotated`).
- [ ] A pruning job deletes Device Certificates whose `notAfter` is older than the retention period (default 1 year, set per profile), writing one `device_certificate.pruned` Audit Event per pass with a count; Audit Events are kept.
- [ ] "SCEP and Enrollment Profiles" is removed from the out-of-scope list in `.scratch/certificate-platform/spec.md`.
