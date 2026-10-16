# Spec: Device enrollment (SCEP, Intune first)

Status: ready-for-agent

## Problem Statement

Organizations replacing DigiCert Trust Lifecycle Manager use it to issue client certificates to their managed devices, mostly through Microsoft Intune, for Wi-Fi (802.1X), VPN and other client authentication. Intune delivers these certificates over SCEP. The platform has no SCEP endpoint, no way to validate an Intune enrollment, and no inventory for certificates that belong to devices rather than to Owners. Without these, an Organization cannot move off TLM, and its RADIUS and VPN infrastructure cannot check device certificates against the platform's revocation.

Later, other device management platforms (Kandji/Iru) and network gear will enroll the same way, but with weaker proof of who is asking: Kandji's SCEP profiles support only a static challenge.

## Solution

An Organization Administrator creates an **Enrollment Profile**. It is a protocol-neutral template that fixes the Issuing CA (from a Private CA, per `.scratch/private-ca/spec.md`), validity, key usage, EKU and allowed key types, and names one **Enrollment Validator**: the integration that decides whether an enrollment request may be issued. SCEP is the first way to enroll under a profile, served by the platform at an opaque public URL per profile.

The first Enrollment Validator kind is **Intune**:
- The Organization Administrator configures an Entra app's credentials, held as a Secret.
- For each SCEP request, the platform asks Intune to validate the CSR and its challenge, and reports success or failure back to Intune.
- When Intune retires, wipes or unenrolls a device, it queues a revocation request, and the platform's hourly poll of that queue revokes the device's Certificate.

Each **Device Certificate** is a stored Certificate belonging to its Enrollment Profile, not to a Managed Certificate. It can be searched and revoked, appears on its Issuing CA's CRL until it expires, and is pruned after a retention period the Organization sets. Every issuance, refusal and Revocation is an Audit Event.

The device generates its own key, so the platform never holds a device key. The one key the platform holds as software is the SCEP RA key. It only decrypts SCEP request envelopes and signs SCEP responses, and ADR 0007 records the exception.

## User Stories

1. As an Organization Administrator, I want to create an Enrollment Profile that names an Issuing CA, validity, key usage, EKU and allowed key types, so that every device certificate it issues follows our policy.
2. As an Organization Administrator, I want EKU to default to client authentication, so that the common Wi-Fi/VPN case needs no thought.
3. As an Organization Administrator, I want anything a CSR asks for beyond the profile (other EKUs, CA:true, a longer validity, extra extensions) ignored rather than honoured, so that a device cannot widen its own certificate.
4. As an Organization Administrator, I want a key type or size the profile does not allow refused, so that weak device keys are never certified.
5. As an Organization Administrator, I want each Enrollment Profile to have its own SCEP URL with an opaque id, so that I can paste it into Intune and it reveals nothing about our Organization.
6. As an Organization Administrator, I want to download the CA certificate (root or Issuing CA) that Intune's trusted certificate profile needs, so that devices trust the chain they are given.
7. As an Organization Administrator, I want to configure an Intune Enrollment Validator with our Entra tenant, app ID and app secret, held as a Secret that cannot be read back, so that the platform can validate requests with Intune.
8. As an Organization Administrator, I want to test the Intune Enrollment Validator's connection, so that I know the Entra app works before devices try to enroll.
9. As an Organization Administrator, I want a SCEP request issued only when Intune confirms the challenge and CSR, so that only devices Intune targeted get certificates.
10. As an Organization Administrator, I want Intune told whether each request succeeded or failed, with the issued certificate's details, so that Intune's reports reflect reality.
11. As an Organization Administrator, I want a Device Certificate revoked when Intune says its device was retired or wiped, so that departed devices lose network access without anyone acting.
12. As an Organization Administrator, I want the subject and SANs taken from the CSR once Intune has vouched for them, so that I configure them only once, in Intune's SCEP profile.
13. As an Organization Administrator, I want to set subject/SAN rules on a profile whose Enrollment Validator does not vouch for names, so that a static-challenge integration (Kandji, network gear) cannot be used to get arbitrary names.
14. As an Organization Administrator, I want to see the Device Certificates an Enrollment Profile issued and search them by subject, SAN, serial, Intune device ID and status, so that I can answer "which certificate does this device have?"
15. As an Organization Administrator, I want to revoke a Device Certificate with an RFC 5280 reason, so that I can cut off a lost or compromised device at once.
16. As a RADIUS server or VPN gateway, I want revoked Device Certificates on their Issuing CA's CRL straight away, so that a revoked device fails authentication on my next CRL fetch.
17. As a device, I want `GetCACaps` to advertise what the platform supports (POSTPKIOperation, SHA-256, AES, Renewal where allowed), so that I use the strongest options.
18. As a device, I want `GetCACert` to return the RA certificate and the CA chain, so that I can encrypt my request and verify the response.
19. As a device, I want my `PKCSReq` encrypted with PKCS#1 v1.5 or OAEP accepted, so that I can enroll whatever my SCEP client's padding.
20. As a device, I want a `CertRep` with SUCCESS and my certificate, or FAILURE with a SCEP `failInfo`, so that my client knows what happened.
21. As a device managed by Intune, I want to re-enroll before my certificate expires with a fresh challenge, and get a new certificate, so that I never lose access. The platform schedules nothing for this.
22. As an Organization Administrator, I want an Audit Event for each Device Certificate issued, each refused enrollment (with the reason) and each Revocation (including Intune-triggered ones), so that our SIEM sees device enrollment.
23. As an Organization Administrator, I want expired Device Certificates pruned after a retention period I set (default 1 year), with their Audit Events kept, so that the inventory reflects live devices.
24. As an Organization Administrator, I want to disable an Enrollment Profile, so that it refuses all enrollment while keeping its Device Certificates and CRL entries.
25. As an Organization Administrator, I want to replace a profile's RA certificate before it expires, so that enrollment keeps working.
26. As an Organization Administrator, I want each enrollment endpoint rate limited, so that a flood of requests cannot exhaust the platform or Intune's API.
27. As an Organization Administrator, I want an Enrollment Profile to refuse its own Issuing CA once that CA is retired, so that rollover is explicit: I point the profile at the new Issuing CA and redeploy the trusted certificate profile in Intune.
28. As a Member or Approver, I want Device Certificates kept apart from the Managed Certificate inventory, so that thousands of device certificates do not bury the TLS inventory.
29. As a Platform Operator, I want one Organization's SCEP URLs, RA keys, Intune credentials and Device Certificates isolated from every other's, so that no Organization can enroll against another's CA.
30. As a future integrator, I want Enrollment Validators to be a pluggable kind, like DNS Provider kinds, so that Kandji/Iru (static challenge) and later platforms can be added without changing SCEP or Enrollment Profiles.

## Implementation Decisions

**Vocabulary** (added to `CONTEXT.md`, replacing the "Device certificates (future)" section):
- **Enrollment Profile**: a protocol-neutral template under which devices obtain client Certificates in bulk from a Private CA's Issuing CA, without per-certificate Approval or Owners. It fixes CA, validity, key usage, EKU, allowed key types and its Enrollment Validator. *Avoid*: SCEP profile, template.
- **Enrollment Validator**: the pluggable integration an Enrollment Profile names, which decides whether an enrollment request may be issued, is told the outcome, and may feed Revocations. It declares whether it vouches for the names in a request. Intune is the first kind. *Avoid*: MDM integration (network gear is not an MDM), challenge provider.
- **Device Certificate**: a Certificate issued under an Enrollment Profile. It belongs to the profile, not to a Managed Certificate, has no Owners, and is renewed by the device re-enrolling. *Avoid*: client cert, device cert record.

The out-of-scope list in `.scratch/certificate-platform/spec.md` loses "SCEP and Enrollment Profiles".

**ADR 0007** (written with the Private CA spec) also records the RA key exception:
- Each Enrollment Profile has an RA key pair, generated by the platform as a software RSA key and wrapped by the Organization's data key, like a Secret.
- The RA key is software because SCEP clients commonly encrypt to it with PKCS#1 v1.5, which AWS KMS cannot decrypt (its RSA decryption is OAEP-only).
- It only decrypts enrollment envelopes and signs SCEP responses. Its leak would expose CSRs and the one-time challenges in them, never a device or CA key.
- Its certificate is issued by the profile's Issuing CA, with no CA rights and the EKU and key usage SCEP RA certificates need.

**Enrollment Validator seam.** A pluggable kind with a registry, like DNS Provider kinds. Proposed shape:
- `vouchesForNames: boolean`
- `validate(request)` → allow, or refuse with a reason. The request includes the CSR (DER), the challenge password and the transaction ID.
- `issued(request, certificate)` and `failed(request, reason)`: notifications, at least once, retried in the background and never blocking the device's response.
- an optional revocation feed: a way for the validator kind to tell the platform which Device Certificates to revoke (by serial and issuer) and why, and to be told each outcome, since Intune expects a result for every request.
- `test()`: a connection check.

Its credentials are Secrets, put into the validator only when it runs, never shown or logged.

**Intune Enrollment Validator.** Follows Microsoft's SCEP third-party CA integration (the `Intune-Resource-Access` repo and "Use APIs to add third-party CAs for SCEP to Intune"). The exact contract, with example payloads, is in `docs/research/intune-scep-api.md`:
- It discovers Intune's `ScepRequestValidationFEService` and `PkiConnectorFEService` URLs from Microsoft Graph and authenticates with the client credentials flow. The Entra app needs the Intune `scep_challenge_provider` and Graph `Application.Read.All` application permissions.
- `validate` sends the base64 CSR, with Intune's challenge inside it as the `challengePassword`, and the transaction ID to Intune's `validateRequest`. Intune checks the challenge's signature and expiry, that the profile still targets the device, and that the CSR matches what it expects. Any answer but `Success` is a refusal, with Intune's code as the reason.
- `issued` and `failed` call Intune's success and failure notifications, with the certificate's thumbprint, serial, expiry and issuer, or an HRESULT and description.
- The Intune Enrollment Validator vouches for names.
- Intune's API never returns a device ID. The Intune device ID is taken from the CSR's `IntuneDeviceId://` URI SAN when the administrator's SCEP profile includes one.
- Configuration is the Entra tenant ID, app ID and app secret (a Secret). The platform sends a fixed provider name and version as `callerInfo`.
- `test` gets both tokens and discovers both services. It never calls validation or revocation, which would show in Intune's reports or start the revocation cool-down.
- The revocation feed polls `downloadRevocationRequests` (up to 500 at a time, at most hourly because of Intune's cool-down) once per Entra credential. It matches each request by serial and issuer among the Organization's Device Certificates, and uploads a result for each with `uploadRevocationResults` once the Revocation has committed (`CertificateNotFoundError` for an unknown serial).
- Intune-triggered Revocations use `cessationOfOperation` and record the Enrollment Validator as their actor.

**Name rules.** When the profile's validator does not vouch for names, the profile must carry subject/SAN rules: required subject attributes, allowed SAN types, and patterns per type. Requests that break them are refused. When the validator vouches, the rules are empty and nothing is checked beyond the profile's policy. No validator that doesn't vouch for names is built in this spec, but the profile's rules and their enforcement are built and tested, so that the next kind is only an integration.

**SCEP server** (RFC 8894). Public, unauthenticated routes at an opaque per-profile id. It supports:
- `GetCACaps`, advertising POSTPKIOperation, SHA-256, SHA-512, AES, and SCEPStandard, plus Renewal for validators that allow it;
- `GetCACert`, returning a degenerate PKCS#7 with the RA certificate and the CA chain;
- `PKIOperation` (GET and POST) with `PKCSReq`;
- `RenewalReq` only for validators that allow it (Intune does not use it);
- `GetCertInitial`, answered with the stored result, for clients that poll.

Behaviour:
- **Envelopes:** both PKCS#1 v1.5 and RSA-OAEP key transport (Windows uses OAEP; micromdm's client and Apple use PKCS#1 v1.5), and AES, 3DES or single DES content encryption. Single DES is accepted, never advertised, because micromdm's `scepclient` sends it regardless of `GetCACaps`. Requests signed with SHA-1 are accepted (Windows and micromdm sign with it). CertRep uses the key transport the request used.
- **Responses:** CertRep is always SUCCESS or FAILURE with `failInfo` (badRequest, badMessageCheck, badTime, badCertId), never PENDING.
- **Rate limiting:** per profile and per source address.
- **Over TLS:** Android requires HTTPS for SCEP.

The SCEP and PKCS#7/CMS work uses [ts-scep](https://github.com/northlanddynamics/ts-scep) rather than hand-rolled ASN.1. Its `ScepServer` runs as the profile's RA, so it needs only the RA key, and our handler signs through the Private CA module. It decrypts PKCS#1 v1.5 on Bun, whose `node:crypto` refuses it, with raw RSA and implicit rejection (no padding oracle). It handles the OAEP, single DES and macOS GET-encoding quirks above, and mounts on Hono through its `fetchHandler`.

**Issuance flow per request.**
1. Decrypt the envelope with the RA key and verify its signer.
2. Check the profile is enabled and its Issuing CA is active.
3. Check the CSR's key type and size, and the name rules where they apply.
4. Call the validator's `validate`.
5. Sign with the Issuing CA through the Private CA module, applying the profile's validity (clipped to the Issuing CA's expiry), key usage and EKU, and copying the subject and SANs from the CSR.
6. Store the Device Certificate and write its Audit Event in one Unit of Work.
7. Respond, then notify the validator.

A refusal writes an `enrollment.refused` Audit Event with the reason and no Certificate. A repeated transaction ID is answered with its first result, not issued twice.

**Schema.**
- `enrollment_profile`: Organization, name, opaque public id, Private CA, validity, key usage, EKU list, allowed key types, validator kind and config, the validator's Secret reference, name rules, enabled, retention days, and RA certificate and wrapped key.
- `device_certificate`: profile, serial, fingerprint, subject, SANs, not before and not after, PEM, the validator's device ID (such as Intune's device ID, from the CSR's `IntuneDeviceId://` SAN), transaction ID, revocation (reason and time), and created.
- Device Certificates feed the same Issuing CA CRL as Managed Certificates' Certificates.
- A pruning job deletes Device Certificates whose `notAfter` is older than the profile's retention period. Their Audit Events stay.

**Revocation.** Organization Administrators and the validator's feed revoke Device Certificates, with reasons `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` and `privilegeWithdrawn`. The CRL is regenerated in the same Unit of Work, as in the Private CA spec.

**Permissions.** A new `enrollmentProfile` resource, held only by Organization Administrators: `read`, `create`, `update`, `disable`. A new `deviceCertificate` resource, also Organization Administrators only: `read`, `revoke`. `/api/me` reports them.

**Audit Events** (documented in `docs/audit-events.md`):
- `enrollment_profile.created`, `.updated`, `.disabled`, `.ra_rotated`
- `enrollment_validator.tested`
- `device_certificate.issued`: one per certificate, carrying the profile, serial, subject and device ID
- `enrollment.refused`: carrying the profile, reason, validator and transaction ID
- `device_certificate.revoked`: with the reason, and the validator as actor when Intune triggered it
- `device_certificate.pruned`: a single event per pruning pass, with a count

**Web.** Under the Organization's settings, for Organization Administrators:
- **Enrollment Profiles:** create and edit, Intune setup with a connection test, the SCEP URL and CA certificate for pasting into Intune, RA rotation, and disable.
- **Device Certificates** per profile: a server-paginated searchable list with revoke.

Device Certificates do not appear in the Managed Certificate inventory.

## Testing Decisions

- **What a good test does.** It acts as a device, Intune and a relying party would, through the public SCEP and CRL routes and the platform's API. It checks the SCEP responses, the certificates, the CRL, Intune's recorded calls and Audit Events, never internal tables.
- **The seam.** The existing Seam A harness, with the local KMS. The outside world is replaced by:
  - **An Intune double** (`intune-double.ts`, prior art `oidc-idp-double.ts` and `saml-idp-double.ts`). It records validation requests and success/failure notifications, can be told to refuse, to fail transiently or to be unreachable, can queue revocation requests for serials, and records the revocation results uploaded to it.
  - **A SCEP device helper.** It builds real `GetCACaps`, `GetCACert`, and `PKCSReq` messages with enveloped and signed data, with both PKCS#1 v1.5 and OAEP key transport, and parses CertRep.
- **Interoperability.** One test runs a real third-party SCEP client, `micromdm/scep`'s client, in a container next to Pebble and BIND in `docker-compose.yml`, against the app, and checks it gets a certificate.
- **Scenarios:**
  - happy-path enrollment, checking the profile's EKU, key usage and validity (clipped), subject and SAN from the CSR, the chain to the root, and the CDP;
  - CSR-requested extras ignored;
  - a disallowed key refused;
  - a challenge Intune refuses → FAILURE and `enrollment.refused`, with Intune told of the failure;
  - Intune unreachable → FAILURE, and nothing issued;
  - a repeated transaction ID answered without issuing twice;
  - Intune notified of success with the right serial and thumbprint;
  - an Intune-triggered revocation lands on the CRL;
  - an administrator revocation;
  - a disabled profile refuses enrollment;
  - a retired Issuing CA refuses enrollment;
  - name rules enforced for a validator that does not vouch, using a test-only validator kind registered in the harness;
  - pruning after retention;
  - permissions per role;
  - Organization isolation: one Organization's SCEP URL cannot issue from another's CA;
  - rate limiting.
- **Seam contract.** A contract test of the Enrollment Validator seam, run against the Intune kind with its double, which later kinds reuse.

## Out of Scope

- Enrollment Validator kinds other than Intune, including the static-challenge kind for Kandji/Iru and network gear. The seam and name rules are built, not the kinds.
- Enrollment protocols other than SCEP (EST, ACME device attestation). Enrollment Profiles are protocol-neutral so that these can be added later.
- OCSP.
- Platform-scheduled renewal of Device Certificates. Devices re-enroll.
- Server-side key generation or PKCS#12 delivery: the platform never holds a device key.
- Approval or Owners for Device Certificates.
- Subscribers and per-device notices.
- Holding the RA key in a KMS.
- **Notifications** for Intune validation failures (such as expiring Entra credentials), RA certificate expiry and enrollment refusal spikes. These are deferred until the end of the Private CA and device enrollment work and will be decided then, with the Private CA notices. Until then, these are visible through Audit Events and the UI only.

## Further Notes

- This depends on the Private CA spec: the Issuing CA, the KMS signing seam, the CRL and the public route conventions.
- The SCEP and CRL routes must be reachable from the internet (Intune devices enroll from anywhere), and the CRL also over plain HTTP. The deployment notes must say so.
- Fleet volume means many Audit Events and Device Certificate rows. This is accepted (TLM parity, and SIEM forwarding is where it belongs). The Device Certificate list must paginate on the server, and pruning keeps the table bounded.
- Sources for the Intune and KMS facts this spec relies on:
  - [Use APIs to add third-party CAs for SCEP to Intune](https://learn.microsoft.com/en-us/mem/intune/protect/scep-libraries-apis)
  - `docs/research/intune-scep-api.md`: the Intune API contract, revocation polling and SCEP client padding, from Microsoft's `Intune-Resource-Access` source
  - [Kandji SCEP Profile](https://support.kandji.io/scep): static challenge only
  - [AWS KMS key spec reference](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html): RSA decryption is OAEP-only
