# 11: Name changes and pending Approval

**What to build:** An Owner can propose adding or removing names on an existing Managed Certificate, together with a new CSR covering the new names. The change waits for Approval while Renewal continues with the last approved names. Organization Administrators' changes apply immediately.

**Blocked by:** 06 (Approval), 09 (Renewal Policy and scheduler)

**Status:** done

- [x] An Owner can propose a name change with a matching new CSR; at most one name change is pending at a time.
- [x] While pending, Renewal continues with the last approved names and CSR.
- [x] On approval, the next issuance uses the new names and CSR; on rejection, the change is discarded and the Managed Certificate is otherwise unaffected.
- [x] Name changes by Organization Administrators need no Approval.
- [x] Proposals and decisions are audited and appear in the history view.

## Comments

Implemented; typecheck, the web typecheck and the full Seam A suite pass against Postgres, Pebble and BIND.

- A name change is `POST .../managed-certificates/{id}/name-change` with `{ names, csr }`: all the names the Managed Certificate is to have, and a CSR for exactly those names in the same key algorithm (a new key is fine). Names are the CSR's SAN DNS names and CN taken together, as everywhere; there is no separate CN. Allowed to the Managed Certificate's Owners (new permission `proposeNameChange`, held by owning, as with `renew`) and Organization Administrators.
- **Owner's change**: a `name_change` row, `pending`, with the names and CSR; the Managed Certificate keeps its own names and CSR, so Renewal (scheduler, renew now) is untouched, and `pendingNameChange` shows on it. At most one pending (partial unique index, and checked under the Managed Certificate's row lock; the second gets 409). `POST .../name-change/approve` (reason optional) and `.../reject` (reason required) decide it, for `approval: decide`; whoever proposed cannot decide it (403) and of two decisions at once one wins (409). Rejection discards it and touches nothing else; approval gives the Managed Certificate the new names and CSR.
- **Administrator's change** (`changeNames`, Organization Administrators only): applies as it is made, with no row, only the Audit Event.
- Decisions not in the ticket: applying a change, by approval or by an Administrator, **starts an Issuance of the new names at once** (otherwise the new names would wait up to a Renewal Policy's days for a Certificate); a change (approval or an Administrator's) is refused with 409 while an Issuance of the Managed Certificate runs, so no change is left without a Certificate until the next Renewal; it is made once that has ended. An Administrator's change while another is pending is refused (409): decide it first. A change to the same set of names is refused (422; upload a new CSR instead). Refused (409) while the Managed Certificate is awaiting Approval, rejected or archived.
- An Issuance no longer says it `replaces` the previous Certificate when its names differ from that Certificate's: Pebble refuses such an order.
- Audited, against the Managed Certificate: `name_change.proposed`, `name_change.approved` (with the reason and proposer), `name_change.rejected`, and `managed_certificate.names_changed` for an Administrator's, each with `from` and `to` names. The history view shows them as `names_change_proposed|approved|rejected` and `names_changed`, with `names: { from, to }`. `GET .../approvals` now has `nameChanges` beside `items` (the caller's own left out).
- Web: the pending change is shown on the Managed Certificate, Owners and Administrators get a "Propose a name change" / "Change names" form, Approvers a name-change entry in the "Awaiting Approval" queue, and the history has the new entries. The web has no automated tests.
- Review follow-ups: an archived Managed Certificate's pending change is left out of the queue (it cannot be approved; rejecting it still works). Known, left: the CSR/names validation is now repeated in three routes (create, CSR upload, name change); nobody is notified (20).

### Follow-up: changes that end without a decision

- **Withdraw**: `POST .../name-change/withdraw`, only by whoever proposed the pending change (403 for anyone else, who asks an Approver to reject it; 409 if nothing is pending), for someone who may see the Managed Certificate. Status `withdrawn`, audited `name_change.withdrawn`.
- **Proposer leaves the Organization**: a member-removal hook (`discardNameChangesOfRemoved`, run in the removal's own transaction) discards what they proposed and is still pending: status `discarded`, audited `name_change.discarded` with the reason "its proposer left the Organization".
- **Archive**: there is no Archive yet, so ticket 12 must call `discardPendingNameChange(tx, change, managedCertificate, reason)` (name-change.ts) in the transaction that archives, after locking the Managed Certificate; tested here through that call. Until then nothing archives, and the queue already leaves out an archived one's change.
- Ending a change (decision, withdrawal, discard) updates only a change still pending and checks that it did, so of two at once one wins; the history shows `names_change_withdrawn` and `names_change_discarded`.
