# Shared Challenge enrollment is bounded by Name Rules and an optional device check

Iru (formerly Kandji) can give its SCEP profiles only a static challenge, the same for every device, and that challenge sits in the configuration profile on every Mac it enrolls. So an Enrollment Profile whose validator is Iru checks a Shared Challenge that anyone who copies it from one Mac can present. We accept that rather than leave Iru unsupported, and bound what such a holder can get in two ways:

- **Name Rules**, which every profile whose validator does not vouch for names must carry, limit the subject and SANs to the shapes the Organization allows (by default `CN` as a Mac's serial number).
- **An optional device check.** Given an Iru API token, the profile refuses a request whose serial number is not a device Iru manages now, and is refused when Iru cannot be asked. A holder of the challenge can then get certificates only in the names of real, managed Macs, not invented ones.

We did not require the token, because some Organizations will not hand one over and the profile is still useful without it; the setup screen recommends it, and suggests a shorter validity without it, since there is then no Revocation when a Mac leaves Iru. The Shared Challenge belongs to the Enrollment Profile, not to the Iru validator: the platform makes it, shows it once, keeps at most two (the current one and, while a rotation is under way, the previous one) and checks it before the validator is asked, so that a later static-challenge kind (network gear) reuses the same mechanism.

## Consequences

- A holder of the Shared Challenge can enroll under a real Mac's serial number. Enrolling therefore never revokes another Device Certificate; only a RenewalReq, signed with the certificate it replaces, supersedes it.
- Revoking the certificates of Macs removed from Iru is a per-profile switch, off by default, available only with a token. It revokes a device only after it is missing from two polls in a row, and pauses, revoking nothing, when more than 5% of a profile's active devices go missing at once, so that a faulty or partial answer from Iru cannot revoke a fleet.
