// How Certificate Profiles work, as the Certificate Profiles page explains it: the same sections as
// docs/certificate-profiles.md, shorter. Pure and free of the app's imports, so the server's tests can run it.

/** One part of the guide: its heading, and what it says. */
export interface GuideSection {
  title: string;
  paragraphs: string[];
}

export const CERTIFICATE_PROFILE_GUIDE: GuideSection[] = [
  {
    title: "Setting one up",
    paragraphs: [
      "A profile fixes the issuer (one ACME CA the Organization has an ACME Account with, or one active Issuing CA), the key algorithms a requester's key may have and, for a Private CA, the validity. It gives the starting Renewal Policy, and may name a Team as co-Owner of each Managed Certificate so that it is still looked after when the requester leaves.",
      "Its name rules (exact names, zones, how many names and whether wildcards) narrow what the issuer takes and never widen it: the Issuing CA's Permitted Name Rules and ACME DCV still apply.",
      "Each Managed Certificate keeps the issuer, key algorithm, validity and Renewal Policy it was made with, so editing a profile, even pointing it at another issuer, changes only what is requested after. Its name rules are checked as they are now, on each request and each Name Change.",
    ],
  },
  {
    title: "Proposing through one",
    paragraphs: [
      "New Managed Certificate starts by choosing a profile: the Certificate Authority step is skipped and the Key and CSR step is set to the profile's key algorithm. Custom is offered too, unless the Organization requires a Certificate Profile.",
      "A request by anyone but an Organization Administrator must keep to the profile's name rules and is a Proposal, which an Approver decides; the requester becomes an Owner, with the profile's co-Owner Team. An Organization Administrator's request is created outright and held only to the issuer's limits.",
    ],
  },
  {
    title: "Disabling and enabling",
    paragraphs: [
      "Disabling a profile stops everything being issued under it, until it is enabled again. Nobody can request through it, Organization Administrators included. Its pending Proposals and Name Changes can be rejected, but not approved.",
      "Its live Managed Certificates stop renewing: when one is due it shows as Renewal blocked, its Subscribers are told once, and Renew now is refused. Left so, it will expire. Revoking, downloading and changing Owners, Subscribers or the Renewal Policy carry on.",
      "Enabling it again lets its pending decisions be approved and its Managed Certificates renew, a due one on the scheduler's next pass.",
    ],
  },
  {
    title: "Detaching",
    paragraphs: [
      "To let one Managed Certificate renew while its profile stays disabled, detach it from the profile on its details page. It keeps its settings, names and Owners, becomes an ordinary Managed Certificate, and is no longer held to the profile's name rules. It cannot be attached again.",
    ],
  },
];
