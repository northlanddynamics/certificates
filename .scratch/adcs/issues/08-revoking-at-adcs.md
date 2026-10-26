# 08: Revoking at ADCS

**What to build:** An Owner or Organization Administrator revokes a Certificate from an ADCS CA with an RFC 5280 reason. An Agent carries out `adcs.revoke`, and the Revocation is recorded only once ADCS confirms. A refusal or an unreachable CA is reported and leaves the Certificate unrevoked. A revoked Certificate shows "Revoked" and the CRL Distribution Point URLs read from its own extension, with nothing about when ADCS publishes its CRL. See `.scratch/adcs/spec.md` (Revocation).

**Blocked by:** 02 (revocation recorded on the CA's later confirmation), 06 (TLS Managed Certificates from an ADCS CA).

**Status:** ready-for-agent

- [ ] `adcs.revoke` is in the agent contract and implemented on both sides, with `revoked`, `rejected` and `unreachable` results.
- [ ] The Revocation and its Audit Event are written only on `revoked`, and the reasons map one-to-one.
- [ ] Certificate details show the CDP URLs for every Certificate from an ADCS CA, and "Revoked" once revoked.
- [ ] Revoking is allowed after Archive, as for other CAs.
- [ ] Seam A tests use the ADCS double. Go: the contract test covers revoke, and Seam B covers `adcs.revoke`.
