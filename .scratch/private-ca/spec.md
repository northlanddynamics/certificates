# Spec: Private CA

Status: ready-for-agent

## Problem Statement

The platform obtains Certificates only from Let's Encrypt, so it can manage only publicly trusted TLS. Organizations replacing DigiCert Trust Lifecycle Manager also issue a large amount of privately trusted TLS: internal services, names in private DNS that no public CA will validate, and hosts that should not show up in Certificate Transparency logs. They also need a CA for device certificates, which is covered by the separate device enrollment spec (`.scratch/device-enrollment/spec.md`) and builds on this one. Today these Organizations keep a second PKI, either Active Directory Certificate Services or TLM itself, with its own inventory, approvals and renewal practice. That is the manual certificate handling the platform exists to replace.

Running a CA means holding a CA signing key, and ADR 0002 says the platform never holds private keys.

## Solution

An Organization Administrator can create **Private CAs** in their Organization, and a Managed Certificate can be issued from one instead of from an ACME CA.

- **Hierarchy.** When creating a Private CA, the Organization Administrator chooses one of two setups:
  - **Platform root:** the platform makes a self-signed root and an **Issuing CA** under it.
  - **Organization root:** the platform makes only an Issuing CA and gives its CSR to the Organization Administrator. They sign it with the Organization's own (often offline) root and upload the result.
- **Keys.** Each CA key is a non-exportable key in a KMS/HSM. The platform asks the KMS to sign and never sees the key. A new ADR records this as a scoped amendment to ADR 0002.
- **Issuance.** A Managed Certificate issued from a Private CA goes through the same Issuance, Approval, Renewal, Revocation, Owners and Key Custody as today, but without DCV. Instead, each Private CA has **permitted name rules**. Names outside them are refused when they are proposed, and the platform writes them into the Issuing CA as X.509 name constraints when it made the Issuing CA itself.
- **Validity.** Each Private CA sets a maximum and a default validity for TLS.
- **Revocation status.** Each Issuing CA publishes a CRL at a public, unauthenticated URL.
- **Expiry.** Issuing CAs warn before they expire. Rollover is done by hand: the Organization Administrator creates a new Issuing CA and repoints whatever used the old one. A retired Issuing CA keeps publishing its CRL until its last Certificate expires.

## User Stories

1. As an Organization Administrator, I want to create a Private CA with a platform-made root and Issuing CA, so that an Organization with no PKI can start issuing internal certificates at once.
2. As an Organization Administrator, I want to create an Issuing CA whose CSR I sign with our existing offline root, so that devices and servers which already trust our root trust what the platform issues.
3. As an Organization Administrator, I want to download an Issuing CA's CSR, so that I can take it to our root's signing ceremony.
4. As an Organization Administrator, I want to upload the certificate our root signed for an Issuing CA, and have the platform refuse it if it does not match the CSR's key or is not a CA certificate, so that a mistake there cannot leave us with a broken CA.
5. As an Organization Administrator, I want to upload the root (and any intermediates) above an Issuing CA, so that the platform serves full chains.
6. As an Organization Administrator, I want to give a Private CA a name, a subject DN, a key algorithm (ECDSA P-256 or P-384, RSA 2048, 3072 or 4096) and a lifetime, so that it fits our PKI conventions.
7. As an Organization Administrator, I want each CA's key generated in a KMS/HSM and never exportable, so that a breach of the platform's database or servers exposes no CA key.
8. As an Organization Administrator, I want the platform-made root and its Issuing CA to have separate keys, so that compromising the key that signs every day does not compromise the root.
9. As an Organization Administrator, I want to have several Private CAs, such as one for internal TLS and one for devices, so that rolling or revoking one does not touch the other.
10. As an Organization Administrator, I want to set a Private CA's permitted name rules (exact names and zones), so that it can only issue for the namespaces it is meant for.
11. As an Organization Administrator, I want a platform-made Issuing CA to carry its permitted names as X.509 name constraints, so that relying parties enforce them even if the platform were misused.
12. As an Organization Administrator, I want an Organization-root Issuing CA's permitted names enforced by the platform, and the name constraints our root signed (if any) shown to me, so that I know what relying parties will enforce.
13. As an Organization Administrator, I want to set a Private CA's maximum and default TLS validity (default 397 days), so that certificate lifetimes are a decision we made.
14. As an Organization Administrator, I want to download a Private CA's root and chain, so that I can distribute them to the machines that must trust them.
15. As a Member, I want to propose a Managed Certificate issued from a Private CA, so that I get an internal certificate through the same process as a public one.
16. As a Member, I want names outside a Private CA's permitted name rules refused when I propose them, so that I find out before an Approver spends time on it.
17. As an Approver, I want to see which CA a proposed Managed Certificate will be issued from, so that I can judge the names in that context.
18. As an Owner, I want to choose a validity at or below the Private CA's maximum, so that I can use short-lived certificates where they suit.
19. As an Owner, I want Issuance from a Private CA to need no DCV, so that names in private DNS that a public CA cannot validate can be issued.
20. As an Owner, I want Key Custody to work the same for a Private CA (my CSR, or an Agent's), so that the platform still never holds my key.
21. As an Owner, I want Renewal from a Private CA to follow my Renewal Policy, so that it behaves like the rest of my certificates even though there is no ARI.
22. As an Owner, I want to deploy Private CA Certificates through Deployments and Deployment Scripts with the full chain, so that nothing about deployment changes.
23. As an Owner or Organization Administrator, I want to revoke a Private CA Certificate with an RFC 5280 reason, including `affiliationChanged` and `privilegeWithdrawn`, so that I can record why it was distrusted.
24. As a relying party (a server, load balancer or RADIUS server), I want to fetch each Issuing CA's CRL from the URL in the certificate's CRL Distribution Point, over plain HTTP, so that I can check revocation without a TLS loop or credentials.
25. As a relying party, I want the CRL regenerated as soon as a Certificate is revoked, and again on a schedule before its `nextUpdate`, so that I never see a stale or expired CRL.
26. As an Organization Administrator, I want to see an Issuing CA's expiry, so that I can plan its rollover.
27. As an Organization Administrator, I want no Certificate issued that outlives its Issuing CA (validity is clipped to the Issuing CA's expiry), so that nothing breaks part-way through its life.
28. As an Organization Administrator, I want to create a new Issuing CA and repoint Managed Certificates to it, so that I can roll over before the old one expires.
29. As an Organization Administrator, I want to retire an Issuing CA so that it issues nothing more but keeps publishing its CRL until its last Certificate expires, so that revocation keeps working through rollover.
30. As an Organization Administrator, I want to revoke a platform-made Issuing CA with its root, recorded as a Revocation, so that I can respond to a compromise.
31. As an Organization Administrator, I want every Private CA creation, signed-certificate upload, name-rule change, validity change, retirement and CA Revocation to be an Audit Event, so that our PKI changes are accountable.
32. As a Member or Approver, I want to see which Private CAs exist and their chains, without managing them, so that I can propose against the right one.
33. As a Platform Operator, I want the platform's KMS configuration to decide where CA keys live, with a local key only in development and tests, so that production never has a software CA key.
34. As an Organization Administrator, I want each Organization's CA keys scoped to it in the KMS, so that one Organization's CA keys can never sign for another.

## Implementation Decisions

**ADR 0007: Private CA keys are held in a KMS.** This new ADR amends ADR 0002:
- The platform holds a CA signing key only as a non-exportable KMS/HSM key, and in production it never holds CA key material itself.
- The local KMS implementation, with a software key, exists for development and tests only, like `createLocalKms` today.
- Keys live in the platform's own KMS account, with a separate key per CA and the Organization's id bound in the key's policy or context. A key in the Organization's own cloud account (BYOK/HYOK) is a later implementation behind the same seam.
- ADR 0002 still holds for Managed Certificate keys and device keys: the platform never holds one.

The same ADR also records the SCEP RA key exception from the device enrollment spec, so that both exceptions are written down together.

**KMS seam.** The `Kms` interface gains asymmetric operations:
- create a non-exportable signing key of a given algorithm for a context (the Organization's id), returning an opaque key reference;
- get its public key;
- sign a digest with it.

The local implementation keeps the software key wrapped under its master key. AWS KMS and Azure Key Vault plug in behind the same interface, and neither is built in this spec.

**CA module.** A module issues and revokes from a Private CA. It builds and signs X.509 certificates and CRLs with `@peculiar/x509` (already a dependency), with a signer that calls the KMS. It owns:
- certificate profiles: TLS server (serverAuth EKU, plus clientAuth if the CSR asks), Issuing CA (pathLen 0, name constraints), and root;
- serial number generation: 20 random bytes, positive;
- the AIA and CDP URLs.

**`CertificateAuthority` interface.** A Private CA becomes a second implementation. The interface's account and DCV parts are ACME-specific (`createAccount`, `checkAccount`, `DnsChallengeResponder`, `renewalInfo`), so they need adjusting:
- A Managed Certificate's issuer becomes one of two kinds: **ACME**, which carries today's environment and ACME Account, or **Private CA**, which carries a Private CA id.
- Issuance asks the issuer to issue and gives a DCV responder only to the ACME kind.
- `renewalInfo` returns null for a Private CA.
- `roots` returns the Private CA's root.

Callers of Issuance and Revocation do not change.

**Schema.**
- A `private_ca` table holds the Organization, name, root and issuing certificates (PEM), each key's KMS reference, kind (platform root or Organization root), status (`awaiting_signature`, `active`, `retired`, `revoked`), permitted name rules, maximum and default validity, and the CRL number and `nextUpdate`.
- A Managed Certificate's issuer is either an ACME Account (as today) or a Private CA, never both. Existing rows migrate to ACME.
- Certificate rows record which Private CA issued them, which the CRL needs.
- Revoked serials are what the CRL is built from.

**Issuance without DCV.** For a Private CA, Issuance:
1. checks the CSR's names against the CA's permitted name rules;
2. clips validity to the Managed Certificate's chosen validity, the CA's maximum and the Issuing CA's expiry;
3. signs the certificate and stores it with its chain, in the same Unit of Work as its Audit Events.

There is no ACME order, and the Issuance states and failure codes stay the same. A new failure code covers a name outside the permitted rules, as a backstop to the refusal at proposal time.

**Permitted name rules.** These are exact names and zones, a zone covering the name and everything beneath it. They use the same name normalization as today: DNS names, leading `*.` wildcards, no IP addresses.
- When a Managed Certificate is created, proposed or has a Name Change, names outside the rules are refused with 422.
- A platform-made Issuing CA carries the rules as `permittedSubtrees` dNSName constraints, critical.
- Changing the rules affects only future Issuances. For a platform-made Issuing CA it does not change the constraints already in the certificate, so the UI says that changing them later needs a new Issuing CA.

**Validity.** Each Private CA has a maximum and a default TLS validity in days (default 397, with a maximum the Organization Administrator sets). A Managed Certificate issued from a Private CA may set its own validity at or below the maximum, and otherwise gets the default. The Renewal Policy's rules (days before expiry, never before a tenth of the life) apply unchanged.

**Revocation.** For a Private CA, `revoke` records the Revocation and regenerates the CRL in the same Unit of Work, so it is "revoked by the CA" the moment it commits. The reasons offered for Private CA Certificates are `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` and `privilegeWithdrawn`, with no `certificateHold`. Who may revoke is unchanged: an Owner, or anyone holding `managedCertificate.revoke`.

**CRL.**
- Each Issuing CA has a full CRL, signed by its own key, with a monotonically increasing CRL number.
- `nextUpdate` is 7 days after `thisUpdate`, and a scheduled job reissues the CRL at least 3 days before `nextUpdate`.
- The CRL is served DER-encoded at a public unauthenticated route, over HTTP and HTTPS, at an opaque id (not the Organization's name).
- Each certificate's CDP and AIA (caIssuers) point at public routes on the platform's configured public base URL.
- Expired Certificates are dropped from the CRL once they have expired, as RFC 5280 allows.
- A platform-made root publishes its own CRL, covering its Issuing CA, on the same terms.

**Rollover and retirement.**
- An Issuing CA issues nothing past its own `notAfter`.
- Retiring one sets it to `retired`: it refuses Issuance, Managed Certificates pointing at it can no longer renew until they are repointed, and it keeps its CRL until its last Certificate expires.
- Repointing a Managed Certificate to another Private CA is an Organization Administrator change with no Approval. It must not move the Managed Certificate across issuer kinds, and the names must fall within the new CA's rules.
- There is no automatic rollover.

**Permissions.** A new `privateCa` resource in `permissions.ts`, held only by Organization Administrators: `create`, `update`, `retire`, `revoke`. A `privateCa.read` permission is held by every role, so anyone can see the CAs and download their chains. Choosing a Private CA when creating or proposing a Managed Certificate needs no extra permission beyond today's.

**Audit Events.** New actions, documented in `docs/audit-events.md`:
- `private_ca.created`
- `private_ca.csr_signed` (the uploaded certificate accepted)
- `private_ca.updated` (names, validity)
- `private_ca.retired`
- `private_ca.revoked`
- `private_ca.crl_published`, only when publication fails and then succeeds again, not every routine CRL
- `managed_certificate.issuer_changed`

Issuance and Revocation from a Private CA reuse the existing actions, with the issuer in `detail`.

**API.**
- Organization-scoped routes create, list, read, update, retire and revoke Private CAs, download the CSR and upload the signed certificate (Organization-root kind only), and download the chain.
- Unauthenticated routes serve the CRL and the CA certificates (for AIA).
- Managed Certificate create and propose accept an issuer of either kind.
- `/api/me` reports the new permissions.

**Web.**
- A Private CAs page under the Organization's settings, for Organization Administrators: create with either hierarchy, the CSR download and certificate upload steps, permitted names, validity, status and expiry, and retire.
- The Managed Certificate create, propose and Name Change forms let the user pick a Private CA instead of an ACME CA, show its permitted names, and offer a validity choice.

**Domain docs.**
- `CONTEXT.md`:
  - move **Private CA** out of "future" and redefine it as an Organization's own CA, used for internal TLS and device enrollment, whose keys the platform holds only in a KMS;
  - add **Issuing CA** as the CA certificate and key that actually sign end-entity Certificates, under a platform-made or Organization root;
  - adjust **Certificate Authority** and **Issuance** so that DCV applies only to ACME CAs.
- `.scratch/certificate-platform/spec.md`: remove "Private CA" from the out-of-scope list.

## Testing Decisions

- **What a good test does.** It drives the platform through its HTTP API as a user would, and checks what an outside party would observe: the API's answers, the issued certificate and chain, the CRL, Audit Events and mail. It never checks internal tables or calls private functions.
- **The seam.** The existing Seam A harness: the Hono app in-process against a real Postgres, with Better Auth running for real. The KMS is the local implementation, which is the dev/test KMS rather than a mock. There is no Pebble and no DNS for Private CA Issuance.
- **New test files** (prior art: `issuances.test.ts`, `revocation-archive.test.ts`, `renewal.test.ts`, `organization-changes.test.ts`):
  - creating both hierarchies, including uploading a wrong certificate, a non-CA certificate, or one for another key, and checking the right refusals;
  - issuing from a Private CA through both Key Custody kinds, then verifying the chain to the root, the EKU, the validity clipping, the CDP and AIA, and the name constraints with `@peculiar/x509`;
  - names outside the permitted rules refused at proposal and Name Change;
  - Approval still required for non-administrators;
  - Renewal through the scheduler with ARI absent;
  - Revocation: the CRL fetched from its public route lists the serial with the reason, is signed by the Issuing CA, and has an increasing CRL number and a `nextUpdate`; scheduled CRL reissue at the harness clock;
  - expired serials dropped from the CRL;
  - retire and repoint;
  - permissions per role, and Audit Events for each change;
  - Organization isolation: a Managed Certificate in one Organization cannot be issued from another's Private CA.
- **KMS seam test.** A contract test of the local `Kms` signing operations (create, public key, sign and verify; a key used under another Organization's context is refused). AWS and Azure implementations would later run the same contract test.
- **Agents.** One Deployment scenario issued from a Private CA, in the style of `first-deployment.test.ts`, to show the Agent path needs no change.

## Out of Scope

- OCSP. CRLs only.
- Automatic Issuing CA rollover, and the platform signing CA certificates for Organization roots it does not hold.
- BYOK/HYOK KMS keys in the Organization's own cloud account. Only the seam is built.
- AWS KMS and Azure Key Vault implementations, beyond the interface they plug into. This spec ships with the local implementation, and the production KMS implementation is its own ticket.
- Importing an existing CA's private key. Keys are only ever generated in the KMS.
- Cross-certification, multiple Issuing CAs under one Private CA at once, and policy OIDs or CPS pointers in certificates.
- Delta CRLs and partitioned CRLs.
- Device certificates, Enrollment Profiles and SCEP, which are in `.scratch/device-enrollment/spec.md`.
- **Notifications** for Issuing CA expiry and CRL publication failures. These are deferred until the end of this work and the device enrollment work, and will be decided then, together with the device enrollment notices. Until then, expiry and status are only visible in the UI and API.

## Further Notes

- This spec ships before device enrollment, because it is useful on its own for internal TLS. Device enrollment depends on the Private CA, the KMS signing seam and the CRL from this spec.
- Name constraints in a platform-made Issuing CA cannot be changed without reissuing it, which is a reason to keep the permitted names broad (zones) rather than narrow.
- The public CRL and AIA routes are the platform's first unauthenticated non-auth routes outside `/api/auth`. The deployment notes must say they are served on plain HTTP as well, and must not redirect to HTTPS.
