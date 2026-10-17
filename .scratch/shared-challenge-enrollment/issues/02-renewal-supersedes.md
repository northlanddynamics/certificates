# 02: Renewal supersedes

**What to build:** When a device renews with a SCEP RenewalReq under any profile whose Enrollment Validator allows renewal, the Device Certificate it signed with is revoked as `superseded` in the same change as its replacement is issued, so a renewed device holds one valid certificate. A PKCSReq never revokes another Device Certificate. See `spec.md`, "Renewal supersedes".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] An issued RenewalReq revokes the signing Device Certificate with reason `superseded`, in the same Unit of Work as the new certificate is stored.
- [ ] The Issuing CA's CRL is reissued in that change and lists the superseded serial.
- [ ] A `device_certificate.revoked` Audit Event is written with no actor and `detail.by` `{ "renewal": { "serial": <new serial> } }`; documented in `docs/audit-events.md`.
- [ ] A refused RenewalReq revokes nothing.
- [ ] A PKCSReq whose subject matches an existing Device Certificate revokes nothing.
- [ ] Scenarios use the existing renewing test validator kind through the Seam A harness.
