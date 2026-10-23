// What disabling a Certificate Profile does, in the words its confirmation shows. Pure and free of the app's imports, so
// the server's tests can run it.

/** What awaits Approval under a profile, as reading it reports. */
export interface ProfilePending {
  proposals: number;
  nameChanges: number;
}

const counted = (n: number, one: string) => `${n} ${one}${n === 1 ? "" : "s"}`;

/** What stops once the profile is disabled, and how many pending decisions it holds. */
export function disableConsequence({ proposals, nameChanges }: ProfilePending): string {
  const stops = "Nobody can request a certificate through it, Organization Administrators included, until it is enabled again.";
  const held = [...(proposals > 0 ? [counted(proposals, "Proposal")] : []), ...(nameChanges > 0 ? [counted(nameChanges, "Name Change")] : [])];
  if (held.length === 0) return `${stops} Nothing awaits Approval under it.`;
  const they = proposals + nameChanges === 1 ? "it" : "they";
  return `${stops} ${held.join(" and ")} awaiting Approval will be held: ${they} can be rejected, but not approved until it is enabled again.`;
}
