# Spec: Certificate Profiles

Status: ready-for-agent

## Problem Statement

Any Member may already propose a Managed Certificate, but the form asks them to make decisions they are not equipped to make: which Certificate Authority, which key algorithm, what validity, what Renewal Policy. People who are not PKI specialists choose wrongly, and Approvers spend their time correcting requests rather than judging them. An Organization Administrator has no way to say "this is how we issue internal web certificates" once and have everyone request against it, and no way to keep Members from proposing whatever they like.

## Solution

An Organization Administrator defines **Certificate Profiles**. Each profile fixes the issuer, the key algorithms allowed and, for a Private CA, the validity. It sets the starting Renewal Policy, may name a default Team as co-Owner, and may carry name rules. Every member of the Organization sees the enabled profiles in the New Managed Certificate dialog. Choosing one leaves them only the names to enter and a CSR to supply, made in the CSR Generator with the key algorithm already set. A non-administrator's request is always a Proposal for an Approver to decide: there is no pre-approval. The requester becomes an Owner. An Organization can optionally require its non-administrators to propose only through a profile.

A profile's issuance settings are copied onto each Managed Certificate made from it. Its name rules and whether it is enabled are checked live (ADR 0012). While a profile is disabled, nothing is issued under it: no Proposals, no approvals, no Name Changes and no Renewal. An Organization Administrator can enable it again, or detach individual Managed Certificates from it.

## User Stories

1. As an Organization Administrator, I want to create a Certificate Profile with a name and description, so that members know what it is for.
2. As an Organization Administrator, I want a profile to fix one issuer, an ACME CA or an Issuing CA, so that requesters never choose a CA.
3. As an Organization Administrator, I want an ACME CA the Organization has no ACME Account with, or an Issuing CA that is not active, refused as a profile's issuer, so that a profile can issue from the moment it is saved.
4. As an Organization Administrator, I want to limit a profile to some of the key algorithms its issuer takes, so that requesters use the keys we have standardised on.
5. As an Organization Administrator, I want a profile with a single key algorithm, so that the CSR Generator is set up for the requester without a choice.
6. As an Organization Administrator, I want a Private CA profile to fix the validity, at most its Issuing CA's maximum, so that requesters cannot choose a lifetime.
7. As an Organization Administrator, I want to set a profile's starting Renewal Policy, so that certificates made from it renew sensibly by default.
8. As an Organization Administrator, I want to name a Team as each certificate's co-Owner, so that it is still looked after when the requester leaves.
9. As an Organization Administrator, I want to give a profile name rules (exact names and zones), so that it is clear which names it is for.
10. As an Organization Administrator, I want to limit how many names a request may carry, and whether wildcards are allowed, so that requests stay within what the profile is for.
11. As an Organization Administrator, I want a profile's name rules to narrow the issuer's limits and never widen them, so that Permitted Name Rules and DCV still apply.
12. As an Organization Administrator, I want to edit a profile, including pointing it at another issuer, so that I can keep it current when CAs change.
13. As an Organization Administrator, I want editing a profile to leave existing Managed Certificates unchanged, so that nobody's certificate changes because I changed a profile.
14. As an Organization Administrator, I want a profile whose issuer is no longer usable to refuse Proposals until I point it elsewhere, so that requests do not fail later during Issuance.
15. As an Organization Administrator, I want every profile change written to the audit log, so that changes to how certificates are requested can be reviewed.
16. As a Member, I want to see the enabled profiles when I create a Managed Certificate, so that I pick a ready-made setup instead of filling in technical fields.
17. As a Member, I want to read each profile's description and name rules before choosing it, so that I pick the right one.
18. As a Member, I want the Authority step skipped and the Key step pre-filled when I choose a profile, so that I only enter names and a CSR.
19. As a Member, I want my names checked against the profile's rules as I submit, with the offending names named, so that I can correct them before an Approver sees them.
20. As a Member, I want a CSR for a key algorithm the profile does not allow refused with a clear message, so that I know what to generate.
21. As a Member, I want my request through a profile to become a Proposal, so that an Approver decides it as today.
22. As a Member, I want to become an Owner of what I requested, so that I can renew it, replace its CSR, revoke it and change its Owners once approved.
23. As a Member, I want any attempt to override the profile's issuer, validity or Renewal Policy in my request refused, so that the profile means what it says.
24. As an Approver, I want to see which profile a Proposal came from in the Approval queue, so that I decide with that context.
25. As an Approver, I want to see a Managed Certificate's profile on its details page, so that I know what rules it was made under.
26. As an Organization Administrator, I want my request through a profile created outright, so that profiles add no Approval for me.
27. As an Organization Administrator, I want to be held only to the issuer's limits, not the profile's name rules, so that I keep full control.
28. As an Owner, I want a Name Change on a certificate made from a profile checked against the profile's current name rules, so that a Name Change cannot get around the profile.
29. As an Organization Administrator, I want my own Name Changes on such certificates held only to the issuer's limits, as they apply at once.
30. As an Organization Administrator, I want to disable a profile, so that nothing more is issued under it.
31. As an Organization Administrator, I want a disabled profile to refuse new Proposals from everyone, me included, so that disabled means disabled.
32. As an Approver, I want Proposals and Name Changes from a disabled profile kept pending, rejectable but not approvable, so that I can clear them without them being issued.
33. As an Organization Administrator, I want to re-enable a profile, so that its pending Proposals become approvable and its certificates renew again.
34. As a Member, I want disabled profiles hidden from the profile step, so that I am not offered something that will be refused.
35. As an Organization Administrator, I want to see disabled profiles in the admin list, so that I can re-enable them.
36. As an Owner, I want a certificate made from a disabled profile shown as "Renewal blocked", so that I know why it is not renewing.
37. As a Subscriber, I want one *Renewal blocked* notice when automatic Renewal is blocked, so that the certificate does not expire unnoticed.
38. As an Owner, I want "Renew now" refused with a message naming the disabled profile, so that I know what to ask an administrator for.
39. As an Owner, I want to keep revoking, downloading, changing Owners and Subscribers and changing the Renewal Policy while the profile is disabled, so that only issuing stops.
40. As an Organization Administrator, I want the disable confirmation to say how many live certificates will stop renewing and how many pending decisions will be held, so that I understand the consequence.
41. As an Organization Administrator, I want to detach a Managed Certificate from its profile, so that it renews again while the profile stays disabled.
42. As an Organization Administrator, I want a detached certificate to keep its settings and Owners and no longer be checked against the profile's name rules, so that it becomes an ordinary Managed Certificate.
43. As an Organization Administrator, I want detaching written to the audit log, so that it can be reviewed.
44. As an Organization Administrator, I want an Organization setting requiring non-administrators to propose only through a profile, so that free-form requests stop.
45. As an Organization Administrator, I want that setting off by default, so that existing Organizations keep working.
46. As an Organization Administrator, I want the setting to apply to API keys of those without `managedCertificate.create`, so that scripts cannot get around it.
47. As an Owner of a certificate made without a profile, I want to keep proposing Name Changes when the setting is on, so that existing certificates are not stranded.
48. As a Member, I want "Custom" hidden from the profile step when I may not propose freely, so that I am not offered something that will be refused.
49. As an API user, I want the profile routes and the profile field on Managed Certificates in the OpenAPI document, so that I can request through a profile from a pipeline.
50. As an Organization Administrator, I want a guide explaining profiles, disabling and detaching, so that I can set them up without surprises.

## Implementation Decisions

- **Certificate Profile** is in the glossary, and ADR 0012 records the copied-versus-live decision. Owner, Proposal, Name Change, Renewal and Enrollment Profile are reworded to match.
- A new per-Organization record holds:
  - a name unique within the Organization, and a description;
  - the issuer, stored the way a Managed Certificate stores one (issuer kind with an ACME CA id or an Issuing CA id);
  - the allowed key algorithms;
  - a validity (Private CA only);
  - the starting Renewal Policy;
  - an optional default Team;
  - optional name rules (exact names, zones, a maximum number of names, and whether wildcards are allowed);
  - whether it is enabled.
- A profile is always Key Custody: Owner and names no Subscribers.
- A Managed Certificate gains a nullable reference to the profile it came from. Detaching clears it. Pending Proposals stay linked to their profile.
- Permissions: a new resource `certificateProfile: [read, create, update, disable]`, plus `managedCertificate.detachProfile`.
  - Organization Administrators hold all of it, as they hold every declared permission.
  - Approvers and Members get `certificateProfile.read`, which lists enabled profiles only. Organization Administrators see disabled ones too.
  - `/api/me` reports them, so the web checks permissions and not role names.
- The create-Managed-Certificate route takes an optional profile id.
  - With one, the issuer, validity and Renewal Policy come from the profile, and a request that also gives any of them is refused with 400.
  - The key algorithm must be one the profile allows (422).
  - For a non-administrator, the names must keep to the profile's name rules (422, naming the offending names).
  - The existing names-and-CSR check and the issuer's own checks then run as today.
  - The requester and the default Team are added as Owners, together with any Owners named.
  - Everything is one `UnitOfWork` change, with its Audit Event recording the profile.
  - A disabled profile, or one whose issuer is unusable (an Issuing CA that is not active, or an ACME CA with no ACME Account), refuses the request with 422 for everyone.
- Name rules are checked by one function shared by Proposals and Name Changes, using the existing name normalisation. They narrow the issuer's limits: an Issuing CA's Permitted Name Rules and ACME DCV still apply afterwards.
- Name Changes on a Managed Certificate linked to a profile:
  - a non-administrator's proposal is checked against the profile's current name rules;
  - proposing one while the profile is disabled is refused for everyone;
  - approving one is refused while the profile is disabled.
- Approving a Proposal is refused with 422 while its profile is disabled. Rejecting is always allowed. Editing a profile does not re-check pending Proposals.
- Renewal while a profile is disabled:
  - The rule that a disabled profile issues nothing is enforced where an Issuance begins, so every way in (approval, Name Change, Renewal) meets the same refusal.
  - When a Managed Certificate is due, the scheduler starts no Issuance and records it as renewal-blocked. The *Renewal blocked* notice, a new notification kind, goes to its Subscribers once until it is unblocked.
  - "Renew now" is refused with 422.
  - The Managed Certificate's state reports the block, so the inventory and details pages can show it.
- Revocation, export, Owner and Subscriber changes, Renewal Policy changes and Archive never consult the profile.
- Disabling and enabling are reversible and need `certificateProfile.disable`.
  - The route that reads a profile reports the number of live Managed Certificates linked to it and the number of pending Proposals and Name Changes, for the confirmation.
  - The API takes no acknowledgement, and its description states the consequence.
- Detaching needs `managedCertificate.detachProfile`. It clears the link, writes an Audit Event and changes nothing else. A blocked certificate becomes due for Renewal again at once.
- A new Organization setting, "require Certificate Profile", is off by default and changed with `certificateProfile.update`.
  - When on, a create request without a profile id from a caller lacking `managedCertificate.create` (including that caller's API keys) is refused with 403.
  - It does not affect Name Changes.
  - `/api/me`, or the profile list, reports whether free-form proposing is open to the caller.
- Audit Events: profile created, updated, disabled, enabled; Managed Certificate detached from its profile; Organization setting changed. Each is written with its change, and `docs/audit-events.md` lists them.
- In the web app:
  - A Certificate Profiles admin page sits under the Organization's settings beside Enrollment Profiles, with create, edit, disable and enable. The disable confirmation shows the counts.
  - The New Managed Certificate dialog gains a first step, "Choose a profile", listing the enabled profiles with their descriptions and name rules, plus "Custom" when free-form proposing is open to the caller. On a profile, the Authority step is skipped and the Key step is pre-filled with the profile's key algorithm (or limited to its list).
  - The Approval queue and the details page show the profile, and its disabled state.
  - The details page has a Detach control for Organization Administrators, and shows "Renewal blocked".
  - UI components are added only through the shadcn CLI.

## Testing Decisions

- A good test checks external behaviour only: API responses, Audit Events, notices sent, and what an Issuance produces. It does not check how the code is arranged.
- Seam 1, the main one: the HTTP API through the existing server test harness, with Pebble as the ACME CA and the test KMS for Private CAs. It covers:
  - profile CRUD and issuer validation;
  - proposing through a profile and every refusal;
  - Owners being added;
  - administrators being created outright and not held to name rules;
  - Name Changes checked against current rules;
  - disable and enable with approval refused;
  - "Renew now" refused;
  - detaching;
  - the Organization setting, including through an API key;
  - permissions and Audit Events.
- Seam 2: the renewal scheduler, driven as the existing renewal tests drive it. With the profile disabled, no Issuance starts, the certificate shows as blocked, and *Renewal blocked* is sent to Subscribers once. Re-enabling or detaching makes it renew.
- Seam 3: the existing web tests, only where there is real logic:
  - the profile step offering "Custom" only when allowed;
  - the Authority step skipped and the Key step pre-filled from a profile;
  - the counts in the disable confirmation.
  - No browser tests.
- Prior art: `managed-certificates.test.ts`, `name-changes.test.ts`, `owners-visibility.test.ts`, `enrollment-profile-lifecycle.test.ts`, `renewal.test.ts`, `private-ca-renewal.test.ts`, `notifications.test.ts`, `acme-ca-picker-web.test.ts`.

## Out of Scope

- Pre-approval: Proposals approved automatically within a profile's name rules.
- Restricting a profile to some Teams.
- Key Custody: Agent and Deployments on a profile.
- Default Subscribers on a profile.
- Anonymous or non-member requests (devices use Enrollment Profiles).
- Per-user request quotas.
- Re-checking pending Proposals when a profile is edited.
- Moving an existing Managed Certificate onto a profile.

## Further Notes

- ADR 0012 records why issuance settings are copied while name rules and enabled state are checked live, and that disabling stops Renewal.
- ADR 0002 holds: the platform never sees the requester's private key; the CSR Generator makes it in the browser.
- No Better Auth capability covers this; Teams for the default co-Owner are Better Auth's.
