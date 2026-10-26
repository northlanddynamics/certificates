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
      "A profile picks the CA that issues, the key types a requester may use and, for a Private CA, how long certificates last. It sets the starting Renewal Policy, and can make a Team a co-Owner of each certificate, so someone still looks after it when the requester leaves.",
      "Its name rules say which names, and how many, a request may have. They can only narrow what the CA allows, never widen it.",
      "Each Managed Certificate keeps the settings it was made with, so editing a profile only changes later requests. Name rules are always checked as they are now.",
    ],
  },
  {
    title: "Proposing through one",
    paragraphs: [
      "New Managed Certificate starts by choosing a profile, which makes the CA and key choices for you. Custom is offered too, unless your Organization requires a Certificate Profile.",
      "A member's request must follow the profile's name rules, and becomes a Proposal for an Approver to decide. The requester and the profile's Team become its Owners. An Organization Administrator's request is created straight away.",
    ],
  },
  {
    title: "Disabling and enabling",
    paragraphs: [
      "Disabling a profile stops anything being issued through it, for everyone, until you enable it again. Its pending Proposals and Name Changes can be rejected, but not approved.",
      "Its certificates stop renewing. When one is due, it shows as Renewal blocked and its Subscribers are told. If nothing changes, it will expire. Everything else, such as revoking and downloading, still works.",
      "Enabling it again lets its certificates renew and its pending requests be approved.",
    ],
  },
  {
    title: "Detaching",
    paragraphs: [
      "To let one certificate renew while its profile is disabled, an Organization Administrator can detach it on its details page. It keeps its settings, names and Owners, and is no longer bound by the profile's name rules. This can't be undone.",
    ],
  },
];
