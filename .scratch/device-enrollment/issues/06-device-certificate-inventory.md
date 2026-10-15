# 06: Device Certificate inventory

**What to build:** An Organization Administrator sees the Device Certificates an Enrollment Profile issued and finds one by subject, SAN, serial, Intune device ID or status, across fleets of thousands.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] A server-paginated, filterable API for a profile's Device Certificates (`deviceCertificate.read`, Organization Administrators only).
- [ ] Web: a Device Certificates list per profile with search, status and detail (download the certificate), and the revoke action once ticket 05 lands.
