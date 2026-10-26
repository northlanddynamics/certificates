# Spec: Active Directory Certificate Services as a Certificate Authority

Status: ready-for-agent

## Problem Statement

Many Organizations replacing DigiCert Trust Lifecycle Manager already run Active Directory Certificate Services (ADCS) as their private CA. Its root is already trusted by every domain-joined machine through Group Policy, and their servers, RADIUS and VPN infrastructure already check certificates against it. TLM manages certificates from ADCS through its own connector, and their devices get certificates through NDES.

The platform can issue only from an ACME CA or from one of the Organization's own Private CAs. To move to it, an Organization would have to stand up a new Private CA and distribute a new root to everything that must trust it, or keep TLM and NDES running beside the platform. Neither is acceptable to an Organization whose trust in ADCS is already built.

ADCS also does not fit the platform's existing CA models. Someone else holds its key, its Certificate Templates decide what it issues, it publishes its own CRL, and it sits inside the Organization's network, reachable only with a domain identity.

## Solution

An Organization Administrator adds an **ADCS CA**: a new kind of Certificate Authority, next to ACME CAs and Private CAs. It names the ADCS CA by its config string (`host\CA Name`) and assigns it one or more of the Organization's Agents. Each assigned Agent runs on a domain-joined Windows host as a group managed service account (gMSA).

- The platform never reaches ADCS itself. Every operation is a Work Item that an online assigned Agent carries out with MS-WCCE, as its gMSA. The platform holds no AD credential and no ADCS key.
- The Agent discovers which **Certificate Templates** the CA publishes and the gMSA may enroll on, together with their settings. The web console offers only those, sorted into templates for TLS and templates for devices.
- **TLS.** A Managed Certificate can be issued from an ADCS CA under a Certificate Template, with Approval, Owners, Key Custody, Renewal, Deployments and Certificate Profiles working as they do today. The template decides validity.
- **Devices.** An Enrollment Profile can name an ADCS CA and a Certificate Template in place of an Issuing CA. Devices still enroll at the platform's SCEP URL, and the Enrollment Validator still decides. The platform passes the CSR to ADCS through an Agent and answers PENDING until the certificate comes back. This replaces NDES.
- An ADCS CA may carry **Permitted Name Rules**, which the platform enforces before anything is submitted.
- Templates that need CA manager approval are supported: the request waits at ADCS, and the Agent checks it again until it is issued, denied or 7 days pass.
- Revocation goes through the Agent to ADCS and is recorded once ADCS confirms it. ADCS publishes its own CRL. The platform shows each Certificate's CRL Distribution Point URLs.

## User Stories

### Adding and managing an ADCS CA

1. As an Organization Administrator, I want to add an ADCS CA by its name and config string, so that the platform can issue from the CA my domain already trusts.
2. As an Organization Administrator, I want to assign one or more of our Agents to an ADCS CA, so that it can be reached from inside our network and still work when one Agent is down.
3. As an Organization Administrator, I want the platform to refuse to assign an Agent that does not report a Windows host, so that I learn at once that it cannot reach ADCS.
4. As an Organization Administrator, I want adding an ADCS CA to fetch its CA certificate and chain through an Agent, and to save nothing if the Agent cannot reach the CA, so that a mistyped config string is caught immediately.
5. As an Organization Administrator, I want Agents assigned to an ADCS CA independently of the DNS Providers they relay, so that I can use different hosts for each.
6. As an Organization Administrator, I want to rename an ADCS CA and change its assigned Agents later, so that I can follow changes in our infrastructure.
7. As an Organization Administrator, I want to remove an ADCS CA only while no Managed Certificate, Certificate, Certificate Profile or Enrollment Profile refers to it, so that no history loses its issuer.
8. As an Organization Administrator, I want the platform to refresh the CA's chain when ADCS renews its CA certificate, so that exports and SCEP always carry the current chain.
9. As an Organization Administrator, I want to see the ADCS CA's certificate, its chain and the CRL Distribution Point URLs from its CA certificate, so that I can confirm what clients will check.
10. As a Member, I want to see which ADCS CAs exist and download their chains, so that I can propose against the right one and set up trust where it is missing.
11. As an Organization Administrator, I want to give an ADCS CA optional Permitted Name Rules (exact names and zones), so that the platform refuses to submit a name outside them whatever the template would accept.
12. As an Organization Administrator, I want to be told that an ADCS CA with no Permitted Name Rules relies on Approval alone, so that I choose this knowingly.

### Certificate Templates

13. As an Organization Administrator, I want the platform to discover the Certificate Templates the CA publishes and our gMSA may enroll on, so that I don't have to type template names that I might get wrong.
14. As an Organization Administrator, I want discovery to run when the ADCS CA is added, when I click Refresh, and once a day, so that the list follows changes made in ADCS.
15. As an Organization Administrator, I want only templates set to "Supply in the request" to be offered, so that every Certificate carries the names the CSR asked for and that were approved, and not the Agent's account.
16. As an Organization Administrator, I want to see each template's EKUs, validity, minimum key size, allowed key algorithms and whether it needs CA manager approval, so that I can choose the right one.
17. As an Organization Administrator, I want templates with Server Authentication offered for TLS and templates with Client Authentication offered for devices (a template with both appears in both), so that nobody picks a template that cannot serve the purpose.
18. As an Organization Administrator, I want to hide a discovered template, so that nobody in the Organization can pick it even though the gMSA could use it.
19. As an Organization Administrator, I want a template that has stopped being published, or that the gMSA can no longer enroll on, to show as unavailable, so that I can see why Issuances under it fail.
20. As an Organization Administrator, I want Certificate Profiles and Enrollment Profiles that name an unavailable template to show a warning without being disabled, so that issuing resumes by itself once ADCS is fixed.
21. As an Organization Administrator, I want a template that was unavailable and comes back to be available again on the next discovery, so that nothing has to be reconfigured.

### TLS Managed Certificates

22. As an Organization Administrator, I want to create a Managed Certificate whose issuer is an ADCS CA and one of its TLS templates, so that internal TLS comes from the CA our servers and clients already trust.
23. As a Member, I want to propose a Managed Certificate on an ADCS CA and a TLS template, so that I can get an internal certificate through Approval.
24. As an Approver, I want to see the ADCS CA and template a Proposal or Name Change asks for, so that I approve the template as well as the names.
25. As an Owner, I want my CSR refused before it reaches ADCS when its key does not meet the template's requirements, so that I get a clear reason and not an ADCS error.
26. As an Owner, I want names outside the ADCS CA's Permitted Name Rules refused when I propose them, so that I find out before anything waits for Approval.
27. As an Owner, I want the Issuance to show that it is waiting for an Agent, waiting at ADCS for CA manager approval, issued or failed, so that I know where my certificate is.
28. As an Owner, I want an Issuance held pending at ADCS to fail with that cause after 7 days, so that a forgotten request does not hang for ever.
29. As an Owner, I want an Issuance that ADCS denied to fail with ADCS's reason, so that I know what to fix.
30. As an Owner, I want an Issuance to wait while no assigned Agent is online, and fail after 7 days, so that a short Agent outage does not lose my request.
31. As an Owner, I want the validity of what is issued to be the template's, so that the platform never asks for something ADCS would not honour.
32. As an Owner, I want Renewal of a Managed Certificate on an ADCS CA to follow its Renewal Policy's days, so that it renews in time although ADCS has no renewal window.
33. As an Organization Administrator, I want a Deployment to work for a Managed Certificate on an ADCS CA as for any other, so that the Agent generates the key and deploys each Certificate.
34. As an Organization Administrator, I want a Certificate Profile to name an ADCS CA and one of its TLS templates, so that members can request internal certificates through it.
35. As a Member, I want proposals through such a Certificate Profile to keep to its name rules and the ADCS CA's Permitted Name Rules, so that the rules apply however the request is made.
36. As an Owner, I want to export a Certificate from an ADCS CA with its chain in the usual formats, so that I can install it anywhere.

### Devices

37. As an Organization Administrator, I want to create an Enrollment Profile that names an ADCS CA and one of its device templates in place of an Issuing CA, so that our devices get certificates the network already trusts, without NDES.
38. As an Organization Administrator, I want to name the template the profile's RA certificate is issued under, so that SCEP clients see an RA certificate that chains to our ADCS CA.
39. As an Organization Administrator, I want the RA certificate to be renewed through ADCS before it expires, so that enrollment never stops because of it.
40. As a device, I want my SCEP request answered PENDING while the platform obtains my certificate from ADCS, and the certificate given to me when I poll with GetCertInitial, so that a slow Agent or CA does not fail my enrollment.
41. As a device, I want to be told FAILURE when ADCS denies my request, or when it has been pending for 7 days, so that I stop polling.
42. As an Organization Administrator, I want the Enrollment Validator, the profile's Name Rules and the ADCS CA's Permitted Name Rules all to apply before a device's CSR is submitted, so that ADCS only ever sees requests we have decided to issue.
43. As an Organization Administrator, I want Device Certificates from ADCS listed, searched, revoked and pruned like those from an Issuing CA, so that devices have one inventory whatever their CA.
44. As an Organization Administrator, I want an Enrollment Validator's revocation feed, and RenewalReq's revocation as `superseded`, to revoke Device Certificates at ADCS, so that retired devices lose access.

### Revocation

45. As an Owner, I want to revoke a Certificate from an ADCS CA with an RFC 5280 reason, so that clients stop trusting it.
46. As an Owner, I want the revocation recorded only once ADCS has confirmed it, so that the platform never shows something as revoked that ADCS does not consider revoked.
47. As an Owner, I want a revoked Certificate shown as "Revoked", with the CRL Distribution Point URLs read from the Certificate, so that I can check the CRL that clients will use.
48. As an Owner, I want a revocation that cannot reach an Agent, or that ADCS refuses, to fail with that cause, so that I know it did not happen.

### Audit and permissions

49. As an Organization Administrator, I want adding, editing, refreshing and removing an ADCS CA, hiding a template and changing its Permitted Name Rules to be Audit Events, so that every change to how we issue is accountable.
50. As an Organization Administrator, I want every submission, re-check, issuance, denial, revocation and discovery result to be an Audit Event, so that I can trace any Certificate back to the ADCS request that made it.
51. As an Organization Administrator, I want only Organization Administrators to manage ADCS CAs, so that nobody else can change where the Organization's certificates come from.
52. As a Platform Operator, I want an ADCS CA to belong to one Organization, so that no Organization can issue through another's Agents or CA.

## Implementation Decisions

**Vocabulary** (added to `CONTEXT.md` under Issuance):
- **ADCS CA**: an Organization's Active Directory Certificate Services CA, which the platform issues from and revokes at, always through Agents assigned to it, and never directly. It holds no key of the platform's and serves no CRL of the platform's. A Managed Certificate or an Enrollment Profile on one names it and one of its Certificate Templates. *Avoid*: Microsoft CA, AD CA, enterprise CA.
- **Certificate Template**: an ADCS CA's own template, which decides the validity, key usage and EKUs of what it issues. The platform discovers templates and offers only those it can use. *Avoid*: profile (a Certificate Profile and an Enrollment Profile are the platform's own), template (unqualified).
- **Certificate Authority** becomes "an ACME CA, one of the Organization's Private CAs, or one of its ADCS CAs".
- **Permitted Name Rules** also applies to an ADCS CA. On an ADCS CA, it is enforced only by the platform, never as X.509 name constraints.
- **Issuance** also covers an ADCS CA: an Agent submits the CSR under the template, with no DCV.
- **Revocation** for an ADCS CA: an Agent asks ADCS to revoke, and the revocation is recorded once ADCS confirms it.
- **Enrollment Profile** fixes "the Issuing CA, or an ADCS CA and its Certificate Template".

**ADR** (new, next number): *ADCS is an external CA reached only through Agents.* It records the following:
- The platform holds no AD credential and no ADCS key. Each Agent acts as its own gMSA, so ADCS's own permissions on templates decide what can be issued at all, and the Permitted Name Rules are the platform's narrower check.
- We chose MS-WCCE from a domain-joined Windows Agent over CES/CEP from the platform. CES/CEP would need an AD credential stored as a Secret and CES deployed, and it would expose ADCS to the platform's network.
- CES/CEP is a later transport behind the same Agent seam.
- ADR 0002 and 0007 are unchanged. The SCEP RA key exception holds for ADCS-backed Enrollment Profiles; only the RA certificate's issuer differs.

**Issuer kind.** `adcs` is added to the issuer kinds, with the matching database checks.
- The issuer of a Managed Certificate or Certificate becomes `{ kind: "adcs"; adcsCaId; templateId }`.
- The issuer seam gains an ADCS implementation of issuing and revoking. Issuing is asynchronous: it enqueues a Work Item, and the Issuance completes when the Agent's result arrives.
- There is no renewal window, so Renewal uses the Renewal Policy alone.
- Validity cannot be chosen: validity fields are refused for an ADCS issuer, and the Certificate records what ADCS issued.

**ADCS CA module** (server, new, beside the Private CA module). It owns the ADCS CAs, their assigned Agents, their Permitted Name Rules, their chain, their discovered templates and which templates are hidden.
- An ADCS CA records: name, config string, assigned Agents, the CA certificate and chain, CDP URLs from the CA certificate, optional Permitted Name Rules, and when it last discovered templates and how that went.
- A Certificate Template records: its ADCS name and OID, its display name, EKUs, validity period, minimum key size, allowed key algorithms, whether it needs CA manager approval, whether it supplies the subject from the request, whether the gMSA may enroll, whether it is published, and whether it is hidden. It is "available" when it is published, enrollable and supplies the subject from the request. It is offered for TLS if it has Server Authentication, for devices if it has Client Authentication, and to nobody while hidden.
- Discovery replaces the stored facts each time it runs. Templates no longer reported are kept, marked unavailable, since Managed Certificates and profiles may name them.
- A daily scheduled discovery runs for every ADCS CA, beside the existing schedulers.
- The CA certificate and chain are refreshed on every discovery.
- Only the Agents of the ADCS CA's own Organization can be assigned. The Agent must report `os` as Windows.

**Permissions.** A new `adcsCa` statement with `read`, `create`, `update` and `delete`, mirroring `privateCa`.
- `read`: everyone, so that they can propose against an ADCS CA and see its templates and chain.
- `create`, `update` (which covers assigning Agents, Permitted Name Rules, hiding templates and Refresh) and `delete`: Organization Administrators only.
- `/api/me` reports them as it does other permissions.

**Work Items** (added to the agent contract):
- `adcs.discover`: the ADCS CA's config string. The result is the CA certificate and chain, and the templates with their facts.
- `adcs.submit`: config string, template name and CSR (DER). The result is `issued` (the certificate and its ADCS request ID), `pending` (the request ID), or `denied` (ADCS's disposition message).
- `adcs.check`: config string and request ID. The result has the same shape as submit's.
- `adcs.revoke`: config string, serial number and RFC 5280 reason code. The result is `revoked` or `refused` with a reason.
- Every failure says whether ADCS answered and refused (`rejected`) or could not be reached (`unreachable`), like the DNS relay's errors. An unreachable result moves the Work Item to another online assigned Agent.
- No Work Item carries a secret.

**Pending and timeouts.** The ADCS request ID is stored on the Issuance (or SCEP transaction) as soon as it is known.
- A pending request is checked again on a backoff schedule, at most every 15 minutes, until it is issued or denied, or until 7 days after it was first submitted.
- A Work Item still waiting for an Agent after 7 days fails the Issuance with the cause "no Agent available".
- The Issuance's failure causes gain the ADCS ones: denied, pending too long, no Agent available, template unavailable, rejected by ADCS, and unreachable.

**Name and key checks before submission.** These run in the order they run today, then the ADCS ones: Approval, Certificate Profile name rules, Enrollment Validator, Enrollment Profile Name Rules, then the ADCS CA's Permitted Name Rules (shared with the Issuing CA's matcher), then the template's minimum key size and key algorithms. A refusal never reaches ADCS.

**SCEP.** An ADCS-backed Enrollment Profile answers a valid PKCSReq or RenewalReq with PENDING, records the SCEP transaction with its ADCS request ID, and answers GetCertInitial for it as follows:
- PENDING while ADCS is still working on it
- SUCCESS with the certificate once it is issued
- FAILURE (`badRequest`) once it is denied or times out.

Profiles on an Issuing CA keep answering at once and never PENDING. Device Certificates from ADCS are stored and handled exactly like the others.

**RA certificate.** For an ADCS-backed Enrollment Profile:
- The platform generates the RA key as today.
- An Agent submits the RA CSR under the RA template the Organization Administrator names, which must be available but need not be TLS or device.
- It is renewed the same way when a third of its life is left, and the old RA certificate stays valid until the new one is issued.
- The profile does not serve SCEP until its first RA certificate is issued.

**Revocation.** Revoking a Certificate from an ADCS CA enqueues `adcs.revoke` and records the Revocation only when the result is `revoked`. Device Certificates revoked by the revocation feed and as `superseded` go the same way. The UI shows "Revoked" and the CDP URLs from the Certificate's own extension, with nothing about when ADCS publishes.

**Go Agent.**
- A new package defines an ADCS client interface with five methods: discover, submit, check, revoke and fetch chain. It has two implementations:
  - The real one uses MS-WCCE through CertEnroll and CertCli COM. It is built only for Windows.
  - A fake one is used in tests.
- The Agent handles the four Work Items through this interface.
- On non-Windows builds the interface has no real implementation, and the Agent answers ADCS Work Items as `rejected` with "this Agent cannot reach ADCS".
- The Agent's install documentation covers running as a gMSA, the Enroll right on templates and the "Issue and Manage Certificates" right for revocation.

**Web.**
- An ADCS CAs page next to Private CAs, with add and edit dialogs in the same stepped style, a template table (facts, availability, hide) with Refresh, the chain, and the Permitted Name Rules.
- The issuer pickers for Managed Certificates, Certificate Profiles and Enrollment Profiles offer each ADCS CA with its available, unhidden templates for that purpose.
- The Issuance status shows "waiting for an Agent" and "pending at ADCS".
- Certificate details show the CDP URLs.

**Audit Events.** These events are new:
- `adcsCa.created`, `adcsCa.updated`, `adcsCa.deleted`
- `adcsCa.discovered` (with the templates that changed availability)
- `adcsCa.templateHidden` and `adcsCa.templateShown`
- `adcsCa.requestSubmitted`, `adcsCa.requestPending`, `adcsCa.requestDenied`.

Issuance, Revocation and Device Certificate events are written as today, with the ADCS request ID in their detail. Changes go through the UnitOfWork, so a change and its Audit Events commit together.

## Testing Decisions

Good tests here drive the platform through its HTTP API, its SCEP endpoint and the Agent protocol, as people, devices and Agents do, and check what they can observe: responses, Certificates, statuses, Audit Events and the Work Items an Agent is given. They never assert on tables or internal calls.

- **Seam A: the platform, through the test harness.** Most of the behaviour is tested here.
  - The Agent is the existing stand-in in `agent-double.ts`, extended to answer the ADCS Work Items from a new in-memory **ADCS double** (test support). The double holds a CA key and chain, published templates and their facts, which templates the gMSA may enroll on, a switch to hold requests pending or deny them, and its revocations.
  - It covers:
    - adding (including the refusal when the Agent cannot reach the CA), discovery and its daily schedule, unavailable templates and their warnings, hiding
    - Permitted Name Rules and template key checks refusing before submission
    - Proposal, Approval, Issuance, pending, denial, timeouts and no Agent online
    - Renewal by policy, Name Changes, Certificate Profiles on an ADCS CA, Deployments
    - Revocation recorded only on confirmation
    - permissions and `/api/me`, Audit Events, removal guarded by references, and isolation between Organizations.
  - Prior art: `relayed-dns-providers.test.ts` (relayed Work Items and failover between Agents), `private-ca.test.ts`, `certificate-profiles.test.ts`, `revocation-archive.test.ts`.
- **SCEP through Seam A.** ADCS-backed Enrollment Profiles are tested with the existing SCEP device (`scep-device.ts`), extended to poll with GetCertInitial. The tests cover PENDING then SUCCESS, PENDING then FAILURE, the RA certificate from ADCS and its renewal, the validator, profile Name Rules and Permitted Name Rules, and revocation through the feed and as `superseded`. Prior art: `device-enrollment.test.ts`, `intune-enrollment.test.ts`, `shared-challenge-enrollment.test.ts`, `scep-interop.test.ts`.
- **Seam B: the Go Agent against `platformstub`.** The Agent is given each ADCS Work Item, carries it out with the fake ADCS client, and reports in the contract's shape. The tests check failover reporting (`unreachable` and `rejected`), the non-Windows refusal, and that nothing is logged that should not be. Prior art: `relay_test.go`.
- **ADCS client contract (new seam).** One Go contract test states what every ADCS client keeps:
  - submit, check and revoke results and dispositions
  - template facts
  - "Supply in the request"
  - pending and denied.

  The fake runs it in CI. The real MS-WCCE client runs it behind a build tag on a Windows lab host with ADCS, by hand before release. Prior art: `kms-signing-contract.ts`, `enrollment-validator-contract.ts`.
- **Agent contract.** The new Work Items are added to the OpenAPI contract and covered by `agent-contract.test.ts`.
- **Web.** The issuer pickers and the ADCS CA page get web tests in the style of `acme-ca-picker-web.test.ts`.

## Out of Scope

- Reaching ADCS directly from the platform, or over CES/CEP. Only MS-WCCE from a Windows Agent is built; CES/CEP is a later transport behind the same seam.
- Storing an AD credential of any kind.
- Templates that build the subject from Active Directory.
- Choosing validity for a Certificate from an ADCS CA, including through `EDITF_ATTRIBUTEENDDATE`.
- Discovering or importing certificates ADCS issued outside the platform, and Adoption of them.
- Serving, mirroring or scheduling ADCS's CRL, OCSP for it, and showing when ADCS will next publish.
- Managing ADCS itself: creating or editing templates, granting permissions, approving pending requests from the platform, or renewing the ADCS CA's certificate.
- Holding the RA key in a KMS.
- Enrollment protocols other than SCEP for ADCS-backed Enrollment Profiles.
- **Notifications** for an ADCS CA certificate expiring, a template becoming unavailable, no Agent online, and requests pending too long. These are deferred with the Private CA and device enrollment notices, and are visible through the UI and Audit Events until then.

## Further Notes

- This depends on the Private CA spec (Permitted Name Rules, the issuer seam) and on the device enrollment spec (Enrollment Profiles, SCEP, the RA key). It adds PENDING to SCEP, which neither of them needed.
- ADCS checks a template's permissions against the gMSA, not against the platform user who asked. The platform's Approval and Permitted Name Rules are what stand between a Member and a certificate the domain trusts, which is why the console warns when an ADCS CA has no Permitted Name Rules.
- Template validity is read from the template, but ADCS also caps it at the CA certificate's own end. The Certificate records what was actually issued.
- The deployment notes must say that ADCS-backed SCEP needs only the platform's SCEP URL to be reachable from devices. The CRL is ADCS's, served from wherever its CDP says.
