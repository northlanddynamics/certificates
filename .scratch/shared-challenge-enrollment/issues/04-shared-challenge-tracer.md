# 04: Shared Challenge kind, tracer: create and enroll

**What to build:** An Organization Administrator creates an Enrollment Profile with the Shared Challenge kind of Enrollment Validator, is shown its Shared Challenge once with the SCEP URL, the CA fingerprint and a guide for Iru's SCEP Library Item, and a Mac enrolls by presenting the challenge. See `spec.md`, "Shared Challenge mechanism" and "Shared Challenge validator kind", and ADR 0008.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] A validator kind can declare that it uses a Shared Challenge; the kinds listing reports it.
- [ ] The `shared_challenge` kind does not vouch for names, allows renewal, and has no settings, secret, revocation feed or device ID; its `test` succeeds with a note that there is nothing external to reach. It passes the Enrollment Validator contract test.
- [ ] Creating a profile with it generates a Shared Challenge (at least 128 bits of randomness), returns it in the create response only, and stores only its hash; no later read or Audit Event carries it. `enrollment_profile.created` carries its id.
- [ ] A PKCSReq with the challenge as its challengePassword is issued, with the subject and SANs from the CSR; a missing or wrong one is refused (FAILURE, `badRequest`) with `enrollment.refused`, the reason never quoting what was sent. The comparison is constant time.
- [ ] GetCACaps lists Renewal on such a profile, and a RenewalReq is issued without the challenge.
- [ ] A profile with a kind that uses a Shared Challenge defaults to 90 days' validity; the administrator may set another up to the maximum.
- [ ] One Organization's challenge does not enroll under another Organization's profile, and SCEP rate limiting applies.
- [ ] The web offers "Shared Challenge" in the validator step, described as for Iru (formerly Kandji) and network gear, with an explanation that anyone holding the challenge can enroll and what still bounds them.
- [ ] After creating, a one-time panel shows the challenge with a copy button, the SCEP URL, the CA certificate's SHA-256 fingerprint, and the Iru guide (where each value goes, key size 2048 or more, automatic profile redistribution on).
- [ ] Every profile shows its CA certificate's SHA-256 fingerprint with its SCEP URL.
- [ ] The Shared Challenge kind is in the platform's validator kinds and registered in the harness; `docs/audit-events.md` is updated.
