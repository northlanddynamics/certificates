# 09: Retire, repoint and CA Revocation

**What to build:** An Organization Administrator rolls over by hand: they see an Issuing CA's expiry, add a new Issuing CA under the same root (10), repoint Managed Certificates to it, and retire the old one, which stops issuing but keeps publishing its CRL until its last Certificate expires. They can also revoke a platform-made Issuing CA. See `spec.md`, "Rollover and retirement".

**Blocked by:** 06, 10

**Status:** ready-for-agent

- [ ] Retiring an Issuing CA (`privateCa.retire`) sets it to `retired`: Issuance and Renewal from it are refused with a clear failure, and its CRL keeps being reissued until its last Certificate expires (`private_ca.retired`). The other Issuing CAs under its root keep issuing.
- [ ] An Organization Administrator repoints a Managed Certificate to another Issuing CA, under the same root or another, without Approval, if its names fall within the new Issuing CA's rules; repointing across issuer kinds is refused (`managed_certificate.issuer_changed`).
- [ ] Revoking a platform-made Issuing CA (`privateCa.revoke`) puts it on its root's CRL and stops it issuing, leaving the other Issuing CAs under that root as they are (`private_ca.revoked`).
- [ ] Web: Issuing CA expiry, retire, revoke and repoint.
- [ ] "Private CA" is removed from the out-of-scope list in `.scratch/certificate-platform/spec.md`.
