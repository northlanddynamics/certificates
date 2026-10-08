# 06: Approval

**What to build:** A Member can propose a Managed Certificate (Owner Key Custody, with a CSR). It waits for Approval. An Approver sees a queue, approves or rejects with a reason, and approval triggers issuance automatically. Managed Certificates created by Organization Administrators skip Approval.

**Blocked by:** 02 (Members, roles and Teams), 05 (First Certificate (tracer))

**Status:** ready-for-agent

- [ ] A Member can propose a Managed Certificate with names, key algorithm and CSR; it is created in a pending-Approval state with no Certificates.
- [ ] Approvers and Organization Administrators see the Approval queue.
- [ ] An Approver can approve or reject with a reason; a rejection is visible to the proposer.
- [ ] Approval starts issuance automatically without further action from the proposer.
- [ ] Members cannot approve; Organization Administrators' own Managed Certificates never enter the queue.
- [ ] Proposals, approvals and rejections are audited.
