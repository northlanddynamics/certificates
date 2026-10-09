# 12: Revocation and Archive

**What to build:** Owners and Organization Administrators can revoke a Certificate with a reason. Organization Administrators can Archive a Managed Certificate, which stops Renewal and deployment but keeps it, its Certificates and its history. Nothing revokes automatically.

**Blocked by:** 07 (Owners and visibility), 09 (Renewal Policy and scheduler)

**Status:** ready-for-agent

- [ ] Owners and Organization Administrators can revoke a Certificate with an RFC 5280 reason; the CA is told and the Certificate shows as revoked.
- [ ] Archive is available only to Organization Administrators; archived Managed Certificates stop renewing and deploying.
- [ ] Archived Managed Certificates, their Certificates and history remain visible under the archived filter and are never hard-deleted.
- [ ] Archiving, name changes and removing users never revoke anything.
- [ ] Revocations and archives are audited.

## Notes from ticket 11

- Archiving must also discard a pending name change of the Managed Certificate: call `discardPendingNameChange(tx, change, managedCertificate, "the Managed Certificate was archived")` (server/src/name-change.ts) in the archive's transaction, after locking the Managed Certificate (`lockManagedCertificate`), and add a scenario for it. `refusalToChangeNames` already refuses new name changes of an archived one.
