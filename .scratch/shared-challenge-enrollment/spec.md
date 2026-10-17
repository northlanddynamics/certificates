# Spec: Shared Challenge enrollment (Iru and network gear)

Status: ready-for-agent

## Problem Statement

Organizations replacing DigiCert Trust Lifecycle Manager also manage Macs with Iru (formerly Kandji), and want those Macs to get Wi-Fi and VPN client certificates from their Private CA the way Intune-managed devices already do. Iru's SCEP profile can carry only a static challenge, the same for every Mac, and the platform has no Enrollment Validator that accepts one: today the only kind is Intune, which needs a per-device challenge Intune issues. Network gear has the same limitation. So these devices cannot enroll at all.

Every Enrollment Profile whose validator does not vouch for names must also carry Name Rules today. But Iru fills in each Mac's subject and SANs from its own variables, which the platform cannot know or check, so requiring rules would mean guessing at a format the Organization does not control.

Two smaller gaps surface on the way. Apple's SCEP payload defaults to a 1024-bit key, which every Enrollment Profile refuses, with no way to accept it. And a device that renews with a RenewalReq leaves its old Device Certificate valid until it expires.

## Solution

A new Enrollment Validator kind, **Shared Challenge**, lets a device enroll by presenting the profile's Shared Challenge: one secret the platform generates, shows once, and checks for every request. An Organization Administrator creates an Enrollment Profile with this kind, copies the SCEP URL, the Shared Challenge and the CA fingerprint into Iru's SCEP Library Item (the setup screen guides them), and Macs enroll. When the challenge leaks or is due for a change, the administrator rotates it; the previous one keeps working until they retire it or it expires, so Macs Iru has not yet reached keep enrolling.

The platform does not try to tie such a certificate to a device (ADR 0008). It copies the subject and SANs from the CSR, bounded by the Issuing CA's Permitted Name Rules and by Name Rules if the administrator adds any; Name Rules become optional for every validator that does not vouch for names. Because nothing revokes these certificates automatically, Shared Challenge profiles default to a 90-day validity, which Iru's automatic profile redistribution renews without anyone acting.

The kind allows renewal: a Mac may renew with a RenewalReq signed by its current Device Certificate. For every validator kind that allows renewal, a successful renewal now revokes the certificate it was signed with as `superseded`.

Any Enrollment Profile may also allow 1024-bit RSA keys, never by default and with a warning; Device Certificates with such keys carry a "Weak key" badge and can be filtered for.

## User Stories

1. As an Organization Administrator, I want to create an Enrollment Profile whose Enrollment Validator is the Shared Challenge kind, so that Macs managed by Iru can enroll over SCEP.
2. As an Organization Administrator, I want the platform to generate the Shared Challenge, so that it is long and random and never a weak value someone chose.
3. As an Organization Administrator, I want the Shared Challenge shown to me once, when it is made, so that I can paste it into Iru and the platform never shows it again.
4. As an Organization Administrator, I want the platform to keep only what it needs to check the Shared Challenge, not the challenge itself, so that a leak of the platform's database does not reveal it.
5. As an Organization Administrator, I want a request without the Shared Challenge, or with a wrong one, refused with an `enrollment.refused` Audit Event, so that only devices given the challenge enroll and my SIEM sees the attempts.
6. As an Organization Administrator, I want to rotate the Shared Challenge, getting a new one shown once, so that I can replace a challenge that has leaked or is old.
7. As an Organization Administrator, I want the previous Shared Challenge to keep working after a rotation, so that Macs Iru has not yet sent the new profile to can still enroll.
8. As an Organization Administrator, I want to set when the previous Shared Challenge expires when I rotate, so that the overlap ends on its own.
9. As an Organization Administrator, I want to retire the previous Shared Challenge at once, so that I can cut off a leaked challenge as soon as Iru has redeployed.
10. As an Organization Administrator, I want a rotation refused while a previous Shared Challenge is still valid, so that a profile never holds more than two.
11. As an Organization Administrator, I want to see, for each Device Certificate, whether it was issued under the current or the previous Shared Challenge, so that I can tell when the previous one has stopped being used.
12. As an Organization Administrator, I want each rotation and each retirement or expiry of a Shared Challenge recorded as an Audit Event, never with the challenge in it, so that changes to who can enroll are traceable.
13. As an Organization Administrator, I want a Shared Challenge profile to default to a 90-day validity, so that a lost Mac's certificate stops working soon without anyone revoking it.
14. As an Organization Administrator, I want to change that validity up to the profile's maximum, so that I can match my own policy.
15. As an Organization Administrator, I want the setup screen to show the SCEP URL, the Shared Challenge, and the CA certificate's fingerprint, so that I can fill in Iru's SCEP Library Item without hunting for them.
16. As an Organization Administrator, I want the setup screen to tell me to set Iru's key size to 2048 or more and to turn on automatic profile redistribution, so that Macs are not refused for a 1024-bit key and renew before their certificates expire.
17. As an Organization Administrator, I want the setup screen to explain that anyone holding the Shared Challenge can enroll, and what still bounds what they can get, so that I choose this kind knowingly.
18. As an Organization Administrator, I want "Shared Challenge" in the validator list, with Iru named in its description, so that I find it when setting up Iru and also for network gear.
19. As an Organization Administrator, I want a profile whose validator does not vouch for names to need no Name Rules, so that I am not forced to describe names Iru fills in.
20. As an Organization Administrator, I want to add Name Rules to such a profile when I do want to limit names, when I create it or later, so that I can still narrow what a holder of the challenge can get.
21. As an Organization Administrator, I want a profile without Name Rules to issue the subject and SANs from the CSR, within the Issuing CA's Permitted Name Rules, so that the names that matter stay within my Organization's zones.
22. As an Organization Administrator, I want a profile whose validator vouches for names still to refuse Name Rules, so that Intune profiles keep working as they do.
23. As a Mac managed by Iru, I want to enroll with a PKCSReq carrying the Shared Challenge, so that I get a Device Certificate with the subject and SANs Iru gave me.
24. As a Mac, I want GetCACaps to list Renewal on a Shared Challenge profile, so that macOS does not report that the server cannot renew.
25. As a Mac, I want to renew with a RenewalReq signed by my current Device Certificate, without the Shared Challenge, so that I prove I hold my previous key.
26. As a Mac reinstalling Iru's profile, I want a fresh PKCSReq with the Shared Challenge to be issued, so that redistribution renews me either way.
27. As an Organization Administrator, I want a Device Certificate revoked as `superseded` when the device renews with a RenewalReq signed by it, for every validator kind that allows renewal, so that a renewed device holds one valid certificate.
28. As an Organization Administrator, I want that Revocation on the Issuing CA's CRL in the same change as the new certificate, with a `device_certificate.revoked` Audit Event, so that relying parties see it at once.
29. As an Organization Administrator, I want a new enrollment never to revoke another Device Certificate, even one with the same subject, so that someone holding the Shared Challenge cannot cut a real Mac off the network.
30. As an Organization Administrator, I want to allow 1024-bit RSA keys on an Enrollment Profile, so that Macs left on Apple's default key size can enroll if I accept the risk.
31. As an Organization Administrator, I want 1024-bit keys never allowed unless I choose them, so that no profile accepts weak keys by accident.
32. As an Organization Administrator, I want a warning when I choose 1024-bit keys that they are breakable and that some RADIUS servers and VPN gateways reject them, so that I understand what I am accepting.
33. As an Organization Administrator, I want a refusal for a key the profile does not allow to say the key's size and the sizes allowed, so that I can tell a Mac left on Apple's default from anything else.
34. As an Organization Administrator, I want Device Certificates with 1024-bit keys marked "Weak key" in the inventory, and a filter for them, so that I can find and replace them later.
35. As an Organization Administrator, I want allowing 1024-bit keys to show in the profile's Audit Events, so that the choice is traceable.
36. As a RADIUS server or VPN gateway, I want Device Certificates from Shared Challenge profiles on their Issuing CA's CRL like any other, so that a revoked Mac fails authentication on my next CRL fetch.
37. As an Organization Administrator, I want Device Certificates from Shared Challenge profiles searchable by subject, SAN and serial and revocable by hand, so that I can cut off a lost Mac.
38. As a Member or Approver, I want nothing about Shared Challenge profiles visible to me, so that device enrollment stays an Organization Administrator's business, as it is today.
39. As a Platform Operator, I want one Organization's Shared Challenge never to enroll under another Organization's profile, so that Organizations stay isolated.
40. As an Organization Administrator, I want Shared Challenge enrollment rate limited like every SCEP endpoint, so that someone guessing challenges cannot exhaust the platform.
41. As a future integrator, I want the Shared Challenge to belong to the Enrollment Profile and be checked by the platform before any validator is asked, so that network gear or another platform with only a static challenge reuses it without new code.

## Implementation Decisions

**Vocabulary.** Already recorded in `CONTEXT.md`: **Shared Challenge**; the **Shared Challenge kind** of Enrollment Validator (Iru and network gear use it; "Iru validator" and "Kandji" are to be avoided); **Name Rules** are optional limits; a RenewalReq supersedes the Device Certificate it is signed with. ADR 0008 records why Shared Challenge enrollment checks no names. This spec supersedes the device-enrollment spec's rule that a profile whose validator does not vouch for names must carry Name Rules (its user story 13).

**Optional Name Rules.**
- A profile whose validator does not vouch for names may have Name Rules or none; a profile whose validator vouches still may not have any.
- With none, the SCEP path skips the Name Rules check and copies the subject and SANs from the CSR; the Issuing CA's Permitted Name Rules apply as always.
- Name Rules can be given when the profile is created and changed or removed by updating it. A change is in `enrollment_profile.updated`'s `changes`.
- The web gets a Name Rules editor in the profile form, shown only for validator kinds that do not vouch for names, empty by default.
- The validator kinds listing keeps saying whether each kind vouches for names; its description and the create endpoint's change from "must carry" to "may carry".

**Shared Challenge mechanism (on the Enrollment Profile).**
- A validator kind declares that it uses a Shared Challenge (a new flag on the kind, alongside `vouchesForNames` and `allowsRenewal`). The listing of kinds reports it, so the web knows to show the challenge.
- When a profile with such a kind is created, the platform generates the Shared Challenge (at least 128 bits of randomness, rendered in characters SCEP clients and Iru's form accept) and returns it in the create response only.
- The platform stores only a hash of each challenge, as it does for Agent credentials, and compares in constant time. It never stores, logs or shows the challenge again.
- A profile holds a current Shared Challenge and at most one previous one, each with an id. The previous one has an expiry, set by the administrator at rotation (a date, required), and is gone once it expires or is retired.
- **Rotate**: a new endpoint makes a new current challenge, shown once in its response, and moves the old current one to previous with the expiry given. It is refused (409) while a previous one is still valid.
- **Retire**: a new endpoint ends the previous challenge at once.
- **Checking**: for a PKCSReq under a profile whose kind uses a Shared Challenge, the platform checks the CSR's challengePassword against the current and the still-valid previous challenge before the validator is asked. A missing or wrong challenge is refused (SCEP FAILURE, `badRequest`) with an `enrollment.refused` Audit Event whose reason says the challenge was wrong, never what was sent. A RenewalReq is not checked for the challenge: its signature by the current Device Certificate is the proof.
- Each Device Certificate records which Shared Challenge (current or previous, by id) it was issued under, or that it came from a renewal. The Device Certificate's details show it, and its `device_certificate.issued` Audit Event carries the challenge id.
- Permissions: rotating and retiring are `enrollmentProfile:update`, held only by Organization Administrators.

**Shared Challenge validator kind.**
- Kind name `shared_challenge`, labelled "Shared Challenge" in the web, described as for Iru (formerly Kandji) and network gear.
- `vouchesForNames: false`, `allowsRenewal: true`, uses a Shared Challenge, no settings, no secret, no revocation feed, no device ID.
- `validate` allows every request that reached it (the platform has already checked the challenge). `issued` and `failed` do nothing. `test` succeeds with a note that there is no external service to reach.
- The profile's default validity is 90 days when its kind uses a Shared Challenge; otherwise the existing default stays.

**Renewal supersedes.**
- When a RenewalReq under any profile is issued, the Device Certificate it was signed with is revoked with reason `superseded`, in the same Unit of Work as the new certificate is stored, with the CRL reissued in that change.
- Its `device_certificate.revoked` Audit Event has no actor and `detail.by` naming the renewal (the new certificate's serial).
- A PKCSReq never revokes any other Device Certificate.

**1024-bit keys.**
- `rsa-1024` joins the device key types. It is never in a profile's allowed key types unless given; the default set stays 2048, 3072 and 4096.
- The web shows a warning when it is chosen.
- A refusal for a disallowed key states the key's type and size and the profile's allowed key types.
- The Device Certificate list gains a "Weak key" badge for 1024-bit keys and a filter for it; the API's list takes the filter and returns the key type.

**Schema.**
- `enrollment_profile`: the current Shared Challenge (id and hash), the previous one (id, hash and expiry), both null for kinds that do not use one.
- `device_certificate`: the key type, and the Shared Challenge id it was issued under (null for a renewal or a kind without one).

**Audit Events** (documented in `docs/audit-events.md`):
- `enrollment_profile.created` gains `sharedChallenge: { id }` for kinds that use one; `nameRules` may now be null for a kind that does not vouch.
- `enrollment_profile.shared_challenge_rotated`: the profile, the new challenge's id, the previous one's id and its expiry.
- `enrollment_profile.shared_challenge_retired`: the profile and the retired challenge's id, with the administrator as actor; with no actor when it expired.
- `device_certificate.issued` gains `sharedChallenge` (`id`) and `keyType`.
- `device_certificate.revoked` for a renewal: `detail.by` is `{ "renewal": { "serial": ... } }`.
- No Audit Event ever carries a Shared Challenge.

**Web.**
- The profile form offers Shared Challenge in the validator step. Choosing it shows the explanation of its trust model and the 90-day default validity.
- After creating, a one-time panel shows the Shared Challenge with a copy button, beside the SCEP URL and the CA fingerprint, with the Iru guide: where each value goes in Iru's SCEP Library Item, key size 2048 or more, automatic profile redistribution on.
- The profile's actions gain Rotate Shared Challenge (asking for the previous one's expiry, then showing the new one once) and Retire previous challenge.
- The CA certificate's SHA-256 fingerprint is shown with the SCEP URL for every profile.

## Testing Decisions

- **What a good test does.** It acts as an Organization Administrator through the platform's API and as a device through the public SCEP routes, and checks the CertRep, the issued certificate, the CRL and Audit Events, never internal tables.
- **The seam.** The existing Seam A harness with the local KMS, as for device enrollment. The Shared Challenge kind is registered in the harness alongside the test kinds. No new double: nothing outside the platform is involved. The SCEP device helper sends the challenge as the CSR's challengePassword, and RenewalReqs as it already does.
- **Interop.** The existing `micromdm/scep` client test gains a case enrolling with a Shared Challenge passed as its challenge, including after a rotation with the previous challenge.
- **Scenarios:**
  - a profile with the Shared Challenge kind is created and the challenge is returned once, never in later reads or Audit Events;
  - enrollment with the current challenge issues, with the subject and SANs from the CSR;
  - a missing or wrong challenge is refused with `enrollment.refused`, and nothing is issued;
  - after a rotation, both challenges enroll; after retirement, or once the expiry passes (by the harness clock), the previous one is refused;
  - a second rotation while a previous challenge is valid is refused;
  - each Device Certificate records the challenge it was issued under;
  - one Organization's challenge does not enroll under another Organization's profile;
  - a profile without Name Rules issues any names within the Issuing CA's Permitted Name Rules, and refuses names outside them;
  - a profile with Name Rules for a non-vouching kind still enforces them; a vouching kind still refuses Name Rules;
  - Name Rules added or removed by updating a profile take effect and are audited;
  - GetCACaps lists Renewal on a Shared Challenge profile; a RenewalReq issues without the challenge and revokes the signing certificate as `superseded`, on the CRL, with its Audit Event; the same holds for the existing renewing test kind;
  - a PKCSReq with the same subject as an existing Device Certificate revokes nothing;
  - a 1024-bit key is refused by default with a reason naming its size and the allowed types, issued when the profile allows `rsa-1024`, and marked and filterable as a weak key;
  - rotating and retiring are refused to Members and Approvers;
  - rate limiting applies to Shared Challenge profiles.
- **Seam contract.** The Shared Challenge kind passes the Enrollment Validator contract test the Intune kind runs.
- **Prior art.** `device-enrollment.test.ts`, `enrollment-validator-seam.test.ts`, `enrollment-profile-lifecycle.test.ts`, `scep-interop.test.ts`, and the Agent credential's hash-only storage.

## Out of Scope

- Any integration with Iru's API: checking a device against Iru, a device ID, or revoking when a Mac leaves Iru (ADR 0008).
- Parsing or templating the subject or SANs Iru fills in; the platform never builds names.
- An Iru-specific validator kind. Iru is a setup guide for the Shared Challenge kind.
- ACME device attestation (Apple Managed Device Attestation); Iru has no native ACME Library Item.
- Revealing a Shared Challenge again after it was shown, or letting an administrator choose its value.
- Notifications, for example for a Shared Challenge's previous value about to expire; these stay with device-enrollment ticket 09.
- Network gear guides beyond the kind's description.

## Further Notes

- The facts about Iru come from search excerpts of Iru's and partners' docs, which could not be read in full, and no Iru tenant is available to test against. The design depends on none of the unconfirmed ones: it reads nothing from the subject or SANs.
  - Iru's SCEP Library Item supports only a static challenge: [Kandji SCEP Profile](https://support.kandji.io/scep), [Iru: configure the SCEP Library Item](https://docs.iru.com/en/endpoint/library/library-items-profiles/configure-the-scep-library-item)
  - [Iru brand update](https://docs.iru.com/en/iru/platform-overview/iru-brand-update.md)
  - Apple's SCEP payload, with its 1024-bit default key size: [com.apple.security.scep](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.scep.yaml)
- That an Iru profile reinstall sends a fresh PKCSReq rather than a RenewalReq is inferred. Both are handled.
- Builds on `.scratch/device-enrollment/spec.md`, which is implemented.
