import type { Tx } from "./db/client";

/**
 * Runs inside the transaction that removes a user from an Organization, so whatever depends on the
 * user's membership (Teams now; Managed Certificate Owners and Subscribers once those exist) is
 * cleaned up atomically with the removal and its Audit Event. A throwing hook rolls everything back.
 */
export type MemberRemovalHook = (tx: Tx, removed: { organizationId: string; userId: string }) => Promise<void>;

export const memberRemovalHooks: MemberRemovalHook[] = [];
