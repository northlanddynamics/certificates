# Certificate Profiles

A Certificate Profile is an Organization Administrator's template for Managed Certificates, which any member of the Organization may propose against. It says once how a kind of certificate is issued: from which issuer, with which keys, for how long and how it renews. A requester who chooses it is left only the names to enter and a CSR to supply. Unlike an Enrollment Profile, which issues Device Certificates to devices, a Certificate Profile makes Managed Certificates, which need Approval and have Owners.

Only Organization Administrators create, edit, disable and enable profiles, under Administration → Certificate Profiles in the web app or `/api/organizations/{orgId}/certificate-profiles`. Everyone in the Organization may list the enabled ones, to request against one; Organization Administrators see the disabled ones too.

The rule behind them is recorded in [ADR 0012](adr/0012-certificate-profiles-copy-issuance-settings-check-names-and-state-live.md): a profile's issuance settings are copied onto each Managed Certificate made from it, while its name rules and whether it is enabled are checked live.

## Setting one up

**New profile** on the Certificate Profiles page (`POST /api/organizations/{orgId}/certificate-profiles`) takes:

- **Name** and **Description**: the name is unique within the Organization, and the description is what members read when they choose a profile, so say what it is for.
- **Issuer**: one ACME CA or one Issuing CA, which requesters never choose. An ACME CA the Organization has no ACME Account with, or an Issuing CA that is not active, is refused, so that a profile can issue from the moment it is saved.
- **Key algorithms**: some of those the issuer takes. With one, the CSR Generator is set to it for the requester; with several, the requester chooses among them.
- **Validity**: for a Private CA only, at most its Issuing CA's maximum, or its default when none is given. An ACME CA decides its own.
- **Starting Renewal Policy**: what each Managed Certificate made from it starts with, automatic 30 days before expiry unless given. Its Owners may change it afterwards, as on any Managed Certificate.
- **Co-Owner Team** (optional): a Team made an Owner of each Managed Certificate, together with the requester, so that it is still looked after when they leave.
- **Name rules** (optional): exact names and zones (a zone allows the name and everything beneath it), at most how many names, and whether wildcards are allowed. They narrow the issuer's limits and never widen them: an Issuing CA's Permitted Name Rules and ACME DCV still apply afterwards. A profile without name rules takes any name its issuer does.

A profile is always Key Custody: Owner, so the requester keeps the private key and the platform never sees it (ADR 0002). It names no Subscribers.

**Edit** (`PATCH .../certificate-profiles/{id}`) changes any of these, including pointing the profile at another issuer, which may need its key algorithms or validity changed with it. Managed Certificates already made from it keep what they were made with; new name rules apply to the next request and the next Name Change, and pending Proposals are not checked again.

An Organization may also **require a Certificate Profile** (the checkbox below the list, `PUT .../certificate-profile-settings`), which is off by default. While it is on, whoever may not create a Managed Certificate outright (without `managedCertificate.create`), such as a Member or an Approver, may propose one only through a profile, with their API keys too, and is no longer offered Custom. Organization Administrators are not held to it, unless they use an API key that does not carry `managedCertificate.create`, and Name Changes of existing Managed Certificates are not affected.

## Proposing through one

When there is a profile to choose, **New Managed Certificate** starts with **Choose a profile**, which lists the enabled profiles with their descriptions and name rules, and **Custom** for choosing the Certificate Authority and key by hand, unless the Organization requires a profile. Choosing a profile skips the Certificate Authority step and sets the Key and CSR step to its key algorithm, or limits it to its list. Through the API, give `profileId` to `POST /api/organizations/{orgId}/managed-certificates`; giving `issuer`, `acmeCaId`, `validityDays` or `renewalPolicy` too is refused (400), as the profile fixes them.

The request is refused (422):

- for a CSR whose key algorithm the profile does not allow;
- for a non-administrator's names outside the profile's name rules, naming the names that are;
- for a profile that is disabled, or whose issuer is no longer usable (an Issuing CA that is not active, or an ACME CA the Organization has no ACME Account with), for everyone, until an Organization Administrator points it elsewhere or enables it.

The issuer's own checks then run as for any Managed Certificate. A non-administrator's request is always a Proposal, which an Approver decides as any other; the Approval queue shows the profile it came from. There is no pre-approval. An Organization Administrator's request is created outright, and they are held only to the issuer's limits, not to the profile's name rules.

The requester becomes an Owner, and so does the profile's co-Owner Team, with any Owners named in the request. Once it is approved they may renew it, replace its CSR, revoke it and change its Owners. Its details page shows the profile it was made from.

A Name Change of a Managed Certificate made from a profile is checked against the profile's name rules as they are at the time, so a Name Change cannot get around the profile. An Organization Administrator's own Name Changes are held only to the issuer's limits, as they apply at once.

## Disabling and enabling

**Disable** (`POST .../certificate-profiles/{id}/disable`) means that nothing more is issued under the profile:

- It is hidden from **Choose a profile**, and every request through it is refused, Organization Administrators' too.
- Its pending Proposals, and pending Name Changes of Managed Certificates made from it, stay pending. They may be rejected, but approving one is refused until the profile is enabled again. No new Name Change is proposed.
- **Its live Managed Certificates stop renewing.** When one is due, the scheduler starts no Issuance and shows it as **Renewal blocked**, and its Subscribers are sent one *Renewal blocked* notice until it is unblocked. **Renew now** is refused, naming the disabled profile. Unless the profile is enabled again or the Managed Certificate is detached, its Certificate will expire.

Revoking, downloading, changing Owners, Subscribers and the Renewal Policy, and Archive carry on as before: only issuing stops.

The confirmation states how many live Managed Certificates will stop renewing and how many Proposals and Name Changes it will hold. Through the API, reading the profile (`GET .../certificate-profiles/{id}`) gives the same counts as `linked` and `pending`; disabling takes no acknowledgement.

**Enable** (`POST .../certificate-profiles/{id}/enable`) undoes it: members see the profile again, its pending Proposals and Name Changes can be approved, and its Managed Certificates renew again, a due one on the scheduler's next pass. Unlike an Enrollment Profile's, disabling a Certificate Profile is not for good.

## Detaching

To let one Managed Certificate renew while its profile stays disabled, an Organization Administrator detaches it: **Detach from profile…** on its details page, or `DELETE /api/organizations/{orgId}/managed-certificates/{id}/profile`. It becomes an ordinary Managed Certificate. It keeps its issuer, validity, key algorithm, Renewal Policy, names, Owners and Subscribers. Its Name Changes are no longer checked against the profile's name rules, and the profile being disabled no longer stops its Issuance, so one whose Renewal was blocked renews on the scheduler's next pass.

Detaching cannot be undone: a Managed Certificate is never attached to a profile again, nor is an existing one moved onto a profile. A Proposal cannot be detached, pending or rejected; it stays linked to its profile.

## Audit

Creating a profile records `certificate_profile.created`, editing it `certificate_profile.updated` (a change that changes nothing is not recorded), disabling it `certificate_profile.disabled` and enabling it `certificate_profile.enabled`. Turning the requirement for a profile on or off records `certificate_profile_settings.changed`, and detaching a Managed Certificate `managed_certificate.profile_detached`. A Managed Certificate requested through a profile names it in the `detail` of its `managed_certificate.created` or `managed_certificate.proposed`, and the requester and co-Owner Team are each recorded as `managed_certificate.owner_added`. Their detail is in [audit-events.md](audit-events.md).
