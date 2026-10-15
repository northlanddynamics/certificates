# 09: Retire, repoint and CA Revocation

**What to build:** An Organization Administrator rolls over by hand: they see an Issuing CA's expiry, create a new Private CA, repoint Managed Certificates to it, and retire the old one, which stops issuing but keeps publishing its CRL until its last Certificate expires. They can also revoke a platform-made Issuing CA. See `spec.md`, "Rollover and retirement".

**Blocked by:** 06

**Status:** ready-for-agent

- [ ] Retiring a Private CA (`privateCa.retire`) sets it to `retired`: Issuance and Renewal from it are refused with a clear failure, and its CRL keeps being reissued until its last Certificate expires (`private_ca.retired`).
- [ ] An Organization Administrator repoints a Managed Certificate to another Private CA without Approval, if its names fall within the new CA's rules; repointing across issuer kinds is refused (`managed_certificate.issuer_changed`).
- [ ] Revoking a platform-made Issuing CA (`privateCa.revoke`) puts it on its root's CRL and stops it issuing (`private_ca.revoked`).
- [ ] Web: Issuing CA expiry, retire, revoke and repoint.
- [ ] "Private CA" is removed from the out-of-scope list in `.scratch/certificate-platform/spec.md`.
