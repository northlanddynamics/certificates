// Approval: an Approver's authorization of a Managed Certificate's names. Someone who may not create a Managed
// Certificate outright proposes one; it waits, with no Certificates, until an Approver approves it (which starts its
// Issuance) or rejects it with a reason. The routes that do this are in managed-certificates.ts.

/** `not_required` for a Managed Certificate an Organization Administrator created. */
export const APPROVAL_STATUSES = ["not_required", "pending", "approved", "rejected"] as const;
export type ApprovalStatus = (typeof APPROVAL_STATUSES)[number];
