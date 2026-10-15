# 04: Intune Enrollment Validator

**What to build:** An Organization Administrator connects an Enrollment Profile to their Intune tenant, and from then on only the requests Intune vouches for are issued, and Intune is told each outcome. Follows the research note from ticket 01.

**Blocked by:** 01, 03

**Status:** ready-for-agent

- [ ] An Organization Administrator configures the Entra tenant ID, app ID and app secret (a Secret, never read back) and tests the connection (`enrollment_validator.tested`).
- [ ] Each request is sent to Intune for validation; refused, failing or unreachable Intune answers FAILURE, with nothing issued.
- [ ] Intune is told of success (thumbprint, serial, expiry, issuer) or failure, retried in the background.
- [ ] The Intune kind vouches for names; Intune's device ID is stored on the Device Certificate.
- [ ] An Intune double records validation requests and notifications and can refuse, fail or be unreachable; the seam's contract test runs against it.
- [ ] The Enrollment Profiles page is shown in production once this kind is registered, with the Intune setup and test.
