// The New Managed Certificate dialog's profile step: which Certificate Profiles it offers, which steps follow, and what
// the Key step offers on a profile. Pure and free of the app's imports, so the server's tests can run it.
import type { KeyAlgorithm } from "./csr-generator";

/** What the step needs to know of a profile. */
export interface ProfileChoosable {
  id: string;
  name: string;
  description: string;
  allowedKeyAlgorithms: readonly KeyAlgorithm[];
  enabled: boolean;
}

/** The value of the step's choice for requesting without a profile. */
export const CUSTOM = "custom";

/** What the step offers, in the order listed: the enabled profiles, then Custom when the caller may request without one (`customOpen`). */
export function profileOptions(profiles: readonly ProfileChoosable[], customOpen: boolean): { value: string; title: string; description: string }[] {
  return [
    ...profiles.filter((p) => p.enabled).map((p) => ({ value: p.id, title: p.name, description: p.description })),
    ...(customOpen ? [{ value: CUSTOM, title: "Custom", description: "Choose the Certificate Authority and key yourself." }] : []),
  ];
}

/** The dialog's steps: the profile step only when there are profiles to offer, and no Authority step once a profile is chosen, which fixes the issuer. */
export function stepsFor<S extends { id: string }>(steps: readonly S[], { profilesOffered, profile }: { profilesOffered: boolean; profile: ProfileChoosable | undefined }): S[] {
  return steps.filter((s) => (s.id !== "profile" || profilesOffered) && (s.id !== "authority" || !profile));
}

/**
 * What the Key step offers: a profile's key algorithms, or without one those the chosen CA takes. With one alone it is
 * set for the requester (`chosen` false); otherwise they choose among them.
 */
export function keyStepFor(profile: ProfileChoosable | undefined, caTakes: readonly KeyAlgorithm[]): { keyAlgorithms: readonly KeyAlgorithm[]; chosen: boolean } {
  if (!profile) return { keyAlgorithms: caTakes, chosen: true };
  return { keyAlgorithms: profile.allowedKeyAlgorithms, chosen: profile.allowedKeyAlgorithms.length > 1 };
}
