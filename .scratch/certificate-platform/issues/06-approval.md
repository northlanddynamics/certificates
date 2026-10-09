# 06: Approval

**What to build:** A Member can propose a Managed Certificate (Owner Key Custody, with a CSR). It waits for Approval. An Approver sees a queue, approves or rejects with a reason, and approval triggers issuance automatically. Managed Certificates created by Organization Administrators skip Approval.

**Blocked by:** 02 (Members, roles and Teams), 05 (First Certificate (tracer))

**Status:** done

- [x] A Member can propose a Managed Certificate with names, key algorithm and CSR; it is created in a pending-Approval state with no Certificates.
- [x] Approvers and Organization Administrators see the Approval queue.
- [x] An Approver can approve or reject with a reason; a rejection is visible to the proposer.
- [x] Approval starts issuance automatically without further action from the proposer.
- [x] Members cannot approve; Organization Administrators' own Managed Certificates never enter the queue.
- [x] Proposals, approvals and rejections are audited.

## Comments

Implemented on `main`; typecheck and the full Seam A suite pass against Postgres, Pebble and BIND.

- One create endpoint, two outcomes: `POST .../managed-certificates` creates outright for whoever holds `managedCertificate: create` (Organization Administrators, `approval: not_required`, Issuance starts at once), and otherwise creates a *proposal* for whoever holds the new `managedCertificate: propose` (Members and Approvers): `approval: pending`, no Issuance, no Certificates. The CSR and names are validated the same way for both.
- New permission `approval` (`read`, `decide`): Approvers and Organization Administrators. `GET .../approvals` is the queue (pending proposals the caller may decide, oldest first; one's own are left out, though an Administrator sees an Approver's). `POST .../managed-certificates/{id}/approve` (reason optional) and `.../reject` (reason required) decide it; approving begins the Issuance on the same transaction, attributed to the Approver. Of two decisions made at once one wins and the other gets 409; a decision is final.
- Added rule not in the ticket: whoever proposed cannot decide their own proposal (403), so an Approver's proposal needs another Approver or an Administrator.
- A `Managed Certificate` carries `approval { status: not_required|pending|approved|rejected, proposedBy, decidedBy, decidedAt, reason }`. A proposer sees (list, get, certificates, PEM) the Managed Certificates they proposed, which is how a rejection reaches them; everyone else without `managedCertificate: read` still sees none until 07 gives Members and Approvers their visibility.
- Retrying an Issuance of a pending or rejected proposal is refused with 409. A rejected proposal is final: propose again.
- Audited: `managed_certificate.proposed`, `.approved` (with reason and proposer), `.rejected` (with reason), then the usual `issuance.*`.
- Web: Members and Approvers get a "Propose a Managed Certificate" form; Approvers and Administrators get an "Awaiting Approval" queue with Approve and Reject (reason needed); the inventory shows "Awaiting Approval" and "Rejected by …: reason".

Known, left for the tickets that need them: Approval of name changes (11); the Approver and Members seeing Managed Certificates beyond their own proposals (07); a proposal whose proposer is later removed stays in the queue; nobody is notified of a proposal or decision (20). The web has no automated tests; it builds and typechecks.
