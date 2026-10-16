# 06: Device Certificate inventory

**What to build:** An Organization Administrator sees the Device Certificates an Enrollment Profile issued and finds one by subject, SAN, serial, Intune device ID or status, across fleets of thousands.

**Blocked by:** 02

**Status:** done

- [x] A server-paginated, filterable API for a profile's Device Certificates (`deviceCertificate.read`, Organization Administrators only).
- [x] Web: a Device Certificates list per profile with search, status and detail (download the certificate), and the revoke action once ticket 05 lands. (The revoke action is left to ticket 05.)

## Comments

Done, except the revoke action, which ticket 05 adds with its route.

- API (`server/src/device-certificates.ts`): `GET .../enrollment-profiles/{id}/device-certificates` (paged like the other lists: `page`, `pageSize`, `total`; newest first), with `q` matching part of the subject, a SAN value, the serial (hex of any case, colons allowed) or the device ID, ignoring case, LIKE wildcards literal, and `status` `active`, `expired` or `revoked`. `GET .../device-certificates/{certificateId}` and `.../{certificateId}/certificate` (PEM, the leaf alone; the CA certificates are the profile's `ca-certificate`). All need `deviceCertificate.read`; the resource has only `read` until ticket 05 adds `revoke`.
- The device ID was never stored. An Enrollment Validator kind now says how it knows a device, `deviceIdOf(subjectAltNames)` (optional, in `enrollment-validator.ts`); SCEP stores it on the Device Certificate and in `device_certificate.issued`'s `detail.deviceId`. The Intune kind (ticket 04) should implement it from the `IntuneDeviceId://` URI; the harness's `test_allow` and `test_names` kinds do so already.
- A Device Certificate's `created_at` is now the Unit of Work's time (the platform clock), not the database's, so the list's order follows the clock in tests.
- Search runs as substring matches within one profile (on `device_certificate_profile_idx`); fine for thousands per profile. If profiles grow to hundreds of thousands, a trigram index is the next step.
- Web: `web/src/pages/device-certificates.tsx`, reached from a profile's name or its menu on the Enrollment Profiles page.
