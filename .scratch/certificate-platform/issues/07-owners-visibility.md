# 07: Owners and visibility

**What to build:** Managed Certificates can have Owners (users and/or Teams) or none. Members see only Managed Certificates they own directly or through a Team; Organization Administrators and Approvers see the whole Organization. The inventory has filters and each Managed Certificate has a history view.

**Blocked by:** 02 (Members, roles and Teams), 05 (First Certificate (tracer))

**Status:** done

- [x] Owners (users or Teams) can be added and removed; zero Owners is allowed.
- [x] Members see only Managed Certificates they own directly or through a Team, in both the UI and the API.
- [x] Organization Administrators and Approvers see all Managed Certificates in the Organization.
- [x] The inventory can be filtered by expiring soon, pending Approval, no Owners, Key Custody and archived (later filters such as renewal failing and Agent offline plug into the same mechanism).
- [x] A Managed Certificate's history shows its Certificates, name changes and Approvals. (Certificates and Approvals now; name changes appear once ticket 11 exists, by adding their Audit Event action to `HISTORY_KINDS`.)
- [x] Owner changes are audited.

## Comments

Implemented on `main`; typecheck and the full Seam A suite pass against Postgres, Pebble and BIND.

- **Owners.** `managed_certificate_owner` (a user or a Team, exactly one, unique per Managed Certificate). `POST .../managed-certificates/{id}/owners` (`{type: user|team, id}`) and `DELETE .../owners/{type}/{ownerId}` change them; naming an existing Owner is a no-op, removing a non-Owner is 404, naming a user who is not a member or a Team of another Organization is 422. Owners can also be named when creating or proposing (`owners` in the body). Every Managed Certificate in the API carries `owners` (users by email, Teams by name). Zero is fine.
- **Who may change Owners:** Organization Administrators (new permission `managedCertificate: changeOwners`) and the Owners themselves, directly or through a Team. Approvers and other Members may not. This is a decision the ticket did not make; an Owner who may add another gives them sight of the Managed Certificate.
- **Cleanup.** Removing a member from the Organization takes them off every Managed Certificate's Owners (the member-removal hook, which now receives the `Change` so it can audit), and deleting a Team takes it off (new `TeamRemovalHook`, run from Better Auth's `beforeDeleteTeam`); each removal is audited with `because: member_removed | team_deleted`. Adding an Owner locks the user's membership or the Team in share mode, so an Owner cannot outlive what it names under a concurrent removal.
- **Visibility.** Approvers now hold `managedCertificate: read` and, like Organization Administrators, see the whole Organization. Anyone else sees what they own (directly or through a Team they are in, evaluated at the time of the request) plus what they proposed (kept from 06), in the list and in every read (get, Certificates, PEM, history); the rest is 403 whether or not it exists.
- **Filters.** `GET .../managed-certificates?expiringSoon=true&pendingApproval=true&noOwners=true&keyCustody=owner&archived=true`, defined as entries of one registry (`server/src/certificates/inventory-filters.ts`), so renewal failing and Agent offline are one more entry each. They combine and narrow what the caller sees. "Expiring soon" is a current Certificate ending within 30 days (or already ended); a Managed Certificate with no Certificate is not. A meaningless value is 400.
- **Archived** is a new nullable `archived_at` column that nothing sets yet (ticket 12 does). Archived Managed Certificates are left out of the inventory unless `archived=true` is given; they stay readable by id. Ticket 12 may want to revisit hiding them by default.
- **History.** `GET .../managed-certificates/{id}/history`: creation or proposal, approvals and rejections (with reasons) and each Certificate issued, oldest first, read from the audit log and the Certificates. Name changes (11) and Deployment Runs (18) add their Audit Event action to `HISTORY_KINDS` in `server/src/certificates/history.ts`.
- **Audited:** `managed_certificate.owner_added` and `.owner_removed`, with the user's email or the Team's name in `detail.owner`.
- **Deciding Owners is yours to confirm:** letting Owners change Owners is my call, not the ticket's; restricting it to Organization Administrators is one line in `findOwnable` (`server/src/certificates/managed-certificate-reader.ts`).
- Web: filter checkboxes and a Key Custody select above the inventory; each Managed Certificate shows its Owners with add/remove for Administrators and direct Owners; the proposal form takes Owners; a History disclosure per Managed Certificate. The web has no automated tests; it builds and typechecks.

Known, left for the tickets that need them: Subscribers are not cleaned up on removal (20); a Team's member who owns through the Team sees no add/remove controls in the web, though the API lets them; "renew now" for Owners (09).
