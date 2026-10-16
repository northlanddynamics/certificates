# 09: Retire, repoint and CA Revocation

**What to build:** An Organization Administrator rolls over by hand: they see an Issuing CA's expiry, add a new Issuing CA under the same root (10), repoint Managed Certificates to it, and retire the old one, which stops issuing but keeps publishing its CRL until its last Certificate expires. They can also revoke a platform-made Issuing CA. See `spec.md`, "Rollover and retirement".

**Blocked by:** 06, 10

**Status:** done

- [x] Retiring an Issuing CA (`privateCa.retire`) sets it to `retired`: Issuance and Renewal from it are refused with a clear failure, and its CRL keeps being reissued until its last Certificate expires (`private_ca.retired`). The other Issuing CAs under its root keep issuing.
- [x] An Organization Administrator repoints a Managed Certificate to another Issuing CA, under the same root or another, without Approval, if its names fall within the new Issuing CA's rules; repointing across issuer kinds is refused (`managed_certificate.issuer_changed`).
- [x] Revoking a platform-made Issuing CA (`privateCa.revoke`) puts it on its root's CRL and stops it issuing, leaving the other Issuing CAs under that root as they are (`private_ca.revoked`).
- [x] Web: Issuing CA expiry, retire, revoke and repoint.
- [x] "Private CA" is removed from the out-of-scope list in `.scratch/certificate-platform/spec.md`.

## Comments

> *Implemented by AI (`claude/private-ca-9`).*

Notes from the implementation:
- Routes: `POST …/private-cas/{id}/issuing-cas/{issuingCaId}/retire` (`privateCa.retire`), `POST …/issuing-cas/{issuingCaId}/revocation` with an RFC 5280 `reason` (`privateCa.revoke`), and `PUT …/managed-certificates/{id}/issuer` with `{ issuer: { kind: "private_ca", issuingCaId } }`.
- Repointing needs a new permission, `managedCertificate.changeIssuer`, which only Organization Administrators hold. It checks the current names, and those of a name change pending Approval, plus the validity it chose, against the new Issuing CA; repointing to the same Issuing CA is not an event. It issues nothing: the next Renewal, or "Renew now", comes from the new Issuing CA.
- Only an `active` Issuing CA can be retired; an `active` or `retired` platform-made one can be revoked. An Issuing CA under an Organization's own root is refused (422): that root revokes it.
- A revoked Issuing CA's reasons are `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded` and `cessationOfOperation` (migration 0038 adds `revoked_at` and `revocation_reason` to `issuing_ca`). Its root's CRL lists it until its certificate expires.
- The scheduled CRL pass reissues the CRL of an Issuing CA that no longer issues (retired or revoked) while any Certificate it signed is unexpired, so relying parties that check only the leaf's CRL never see it go stale; a Certificate revoked from one is still put on its CRL at once.
- Web: an Issuing CA row's Expires cell warns ("Roll over") once it ends sooner than its maximum validity; its menu has Retire… and Revoke…; a Managed Certificate's Identity card says when its Issuing CA is retired or revoked and offers "Change Issuing CA…" to Organization Administrators.

