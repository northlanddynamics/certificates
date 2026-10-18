import type { Tx } from "../platform/db/client";
import type { Change } from "../platform/unit-of-work";

/**
 * Runs inside the transaction that removes a user from an Organization, so whatever depends on the user's
 * membership (Managed Certificate Owners, and Subscribers once those exist) is cleaned up atomically with the
 * removal and its Audit Event. It may record Audit Events of its own on `change`. A throwing hook rolls everything back.
 */
export type MemberRemovalHook = (tx: Tx, removed: { organizationId: string; userId: string }, change: Change) => Promise<void>;

/** Runs inside the transaction that deletes a Team, before it is deleted, for whatever refers to the Team. A throwing hook rolls everything back. */
export type TeamRemovalHook = (tx: Tx, removed: { organizationId: string; teamId: string; teamName: string }, change: Change) => Promise<void>;
