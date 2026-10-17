# Shared Challenge enrollment checks no names

Iru (formerly Kandji) can give its SCEP profiles only a static challenge, the same for every device, and that challenge sits in the configuration profile on every Mac it enrolls. So an Enrollment Profile whose validator is the Shared Challenge kind issues to anyone who presents its Shared Challenge, which anyone who copies it from one Mac can do. We accept that rather than leave Iru and network gear unsupported.

The platform does not try to tie such a certificate to a device. Iru fills in the subject and SANs on each Mac from variables the platform cannot know or verify, so parsing them (to find a serial number, check it against Iru's API, or revoke when a Mac leaves Iru) would be guessing at a format we do not control. Instead, what a holder of the challenge can get is bounded by:

- **the Issuing CA's Permitted Name Rules**, which still limit DNS, email and other constrained names to the Organization's zones;
- **Name Rules**, which an Organization Administrator may add but the profile does not require;
- **short validity**: a Shared Challenge profile defaults to 90 days, since nothing revokes its certificates automatically, and Iru reinstalls the profile before expiry;
- **Revocation by hand**, and rotating the Shared Challenge when it leaks.

The Shared Challenge belongs to the Enrollment Profile, not to a validator: the platform makes it, shows it once, keeps at most two (the current one and, while a rotation is under way, the previous one) and checks it before the validator is asked. There is one Shared Challenge kind for Iru and network gear alike; Iru is a setup guide, not a kind.

## Consequences

- A holder of the Shared Challenge can enroll under any name the profile allows, including another device's. Enrolling therefore never revokes another Device Certificate; only a RenewalReq, signed with the certificate it replaces, supersedes it.
- Device Certificates of these profiles carry no device ID; they are found by subject, SAN or serial.
- The CN of such a certificate means nothing to the platform. Whatever relies on it (RADIUS, a VPN) decides what it means.
