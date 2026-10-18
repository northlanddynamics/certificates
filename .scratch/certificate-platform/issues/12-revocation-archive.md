# 12: Revocation and Archive

**What to build:** Owners and Organization Administrators can revoke a Certificate with a reason. Organization Administrators can Archive a Managed Certificate, which stops Renewal and deployment but keeps it, its Certificates and its history. Nothing revokes automatically.

**Blocked by:** 07 (Owners and visibility), 09 (Renewal Policy and scheduler)

**Status:** done

- [x] Owners and Organization Administrators can revoke a Certificate with an RFC 5280 reason; the CA is told and the Certificate shows as revoked.
- [x] Archive is available only to Organization Administrators; archived Managed Certificates stop renewing and deploying.
- [x] Archived Managed Certificates, their Certificates and history remain visible under the archived filter and are never hard-deleted.
- [x] Archiving, name changes and removing users never revoke anything.
- [x] Revocations and archives are audited.

## Notes from ticket 11

- Archiving must also discard a pending name change of the Managed Certificate: call `discardPendingNameChange(tx, change, managedCertificate, "the Managed Certificate was archived")` (server/src/certificates/name-change.ts) in the archive's transaction, after locking the Managed Certificate (`lockManagedCertificate`), and add a scenario for it. `refusalToChangeNames` already refuses new name changes of an archived one.

## Comments

Implemented; typecheck, the web typecheck and the full Seam A suite pass against Postgres, Pebble and BIND. The tests are in `server/test/revocation-archive.test.ts`; revocations are made to Pebble for real.

### Archive

- `POST .../managed-certificates/{id}/archive`, new permission `managedCertificate: archive`, held by Organization Administrators only (not the Managed Certificate's Owners; 403 otherwise). It runs on the `UnitOfWork` under `lockManagedCertificate`, sets `archivedAt`, audits `managed_certificate.archived` (with the names) and calls `discardPendingNameChange(tx, change, mc, "the Managed Certificate was archived")`, as ticket 11 asked. Archiving twice is 409.
- The Managed Certificate now shows `archivedAt`. It leaves the inventory unless `archived=true` (the existing filter), where it, its Certificates and its history remain; nothing deletes a Managed Certificate or a Certificate. The history has an `archived` entry.
- Already enforced, now tested end to end: the scheduler and the asking of the CA about renewal windows skip an archived one (`renewsAutomatically`), and `renew now`, trying again and name changes are refused (409) by `Issuances.begin` and `refusalToChangeNames`. "Deploying" has nothing to stop yet (ticket 18 must refuse archived ones). An Issuance already running when the Managed Certificate is archived is left to finish; its Certificate is kept.
- No unarchive: the ticket does not ask for one.

### Revocation

- `POST .../managed-certificates/{id}/certificates/{certificateId}/revocation` with `{ reason }`: one of `unspecified`, `keyCompromise`, `superseded`, `cessationOfOperation` (the RFC 5280 reasons an ACME subscriber may give and Let's Encrypt honours; others are refused with 400). New permission `managedCertificate: revoke`: Organization Administrators, and the Managed Certificate's Owners whatever their role (as with `renew`). Allowed on an archived Managed Certificate, and on any of its Certificates, not only the current one.
- New `CertificateAuthority.revoke(environment, account, { certificate, reason })` (acting as the ACME account that obtained the Certificate), implemented with acme-client's `revokeCertificate`.
- The CA is told first, inside the change's transaction and under the Managed Certificate's lock, and the revocation is recorded and audited only after it says yes: a CA that refuses is 422, one that cannot be reached 502, and nothing is recorded, so the request can be made again. If the commit itself fails after the CA agreed, the CA has revoked a Certificate the platform does not show as revoked (a retry then gets the CA's "already revoked" as 422); accepted as the narrow window of any call out to a CA.
- A Certificate is immutable (trigger), so a revocation is a row in the new `certificate_revocation` table (migration 0016): certificate, reason, who, when. A Certificate shows `revocation: { reason, revokedAt, revokedBy } | null` wherever it is returned (the Managed Certificate's `currentCertificate`, `.../certificates`, the history). A second revocation is 409 and the CA is not told twice.
- Audited `certificate.revoked` against the Managed Certificate (certificate id, fingerprint, serial, reason); the history shows `certificate_revoked` with the reason.
- Nothing else revokes: the tests record every call to the CA (`harness.revocations`) and show that archiving, an Administrator's name change and removing a user leave it empty.
- Revoking does not issue a replacement or change the Renewal schedule: the Managed Certificate is renewed as usual (a person renews it now, with a new CSR if the key is compromised). Whether a revoked current Certificate should make Renewal due at once is left to the product owner.

### Web

- A Managed Certificate shows `Archived` and its date (and no longer offers renewal, name changes or trying again); Organization Administrators get an Archive control with a confirmation, Owners and Administrators a Revoke control (choose a Certificate and a reason, confirm), a revoked current Certificate is shown in red, and the history has both entries. The web has no automated tests.

### Review follow-ups

- An archived proposal still awaiting Approval was left in the Approval queue and approving it gave a 500: it is now left out of the queue, and approving it (or a decision racing an archive) is refused with 409 and rolled back; it stays awaiting Approval, visible under the archived filter.
- Added scenarios: a Team's member revokes (archived Managed Certificate), two revocations at once (one 409, the CA told once), and a control showing the scheduler does renew the same Managed Certificate before it is archived. The existing Certificate shape test now expects `revocation: null`.
- Known, left: the CA call is made while the Managed Certificate's row lock is held (one HTTP call, which stalls an archive, a renewal or a name change of that Managed Certificate meanwhile); only four RFC 5280 reasons are accepted (those Let's Encrypt honours; widen `REVOCATION_REASONS` for another CA); Better Auth's `leave` endpoint is not exposed, so "removing users" is `remove-member`, tested; small web duplications (`when`, the Owner check) follow the existing pages.
