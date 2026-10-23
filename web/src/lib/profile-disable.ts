// What disabling a Certificate Profile does, in the words its confirmation shows. Pure and free of the app's imports, so
// the server's tests can run it.

/** What awaits Approval under a profile, as reading it reports. */
export interface ProfilePending {
  proposals: number;
  nameChanges: number;
}

/** What disabling a profile holds, as reading it reports: its live Managed Certificates, which stop renewing, and what awaits Approval under it. */
export interface ProfileDisableCounts {
  linked: number;
  pending: ProfilePending;
}

const counted = (n: number, one: string) => `${n} ${one}${n === 1 ? "" : "s"}`;

/** What stops once the profile is disabled: requests, the Renewal of its live Managed Certificates, and the pending decisions it holds. */
export function disableConsequence({ linked, pending: { proposals, nameChanges } }: ProfileDisableCounts): string {
  const stops = "Nobody can request a certificate through it, Organization Administrators included, until it is enabled again.";
  const renewing =
    linked === 0
      ? "No live certificate was made from it."
      : `${counted(linked, "live certificate")} made from it will stop renewing: ${linked === 1 ? "it shows" : "they show"} as Renewal blocked when due, and Renew now is refused.`;
  const held = [...(proposals > 0 ? [counted(proposals, "Proposal")] : []), ...(nameChanges > 0 ? [counted(nameChanges, "Name Change")] : [])];
  if (held.length === 0) return `${stops} ${renewing} Nothing awaits Approval under it.`;
  const they = proposals + nameChanges === 1 ? "it" : "they";
  return `${stops} ${renewing} ${held.join(" and ")} awaiting Approval will be held: ${they} can be rejected, but not approved until it is enabled again.`;
}
