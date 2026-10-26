# 11: Revoking Device Certificates at ADCS

**What to build:** Device Certificates from an ADCS CA are revoked at ADCS in three ways: by an Organization Administrator, by the Enrollment Validator's revocation feed (such as Intune retiring a device), and as `superseded` once the replacement a RenewalReq asked for is issued. Each is recorded only once ADCS confirms, and the device list shows "Revoked" and the CDP URLs. See `.scratch/adcs/spec.md` (Revocation).

**Blocked by:** 08 (Revoking at ADCS), 10 (ADCS-backed Enrollment Profiles over SCEP).

**Status:** ready-for-agent

- [ ] Manual revocation of a Device Certificate from ADCS goes through `adcs.revoke` and is recorded on confirmation.
- [ ] The revocation feed revokes at ADCS, and reports each outcome back to the Enrollment Validator only once ADCS has answered.
- [ ] RenewalReq's `superseded` revocation happens only after the replacement is issued and ADCS confirms.
- [ ] A refused or unreachable revocation is reported and retried as the feed's rules already say.
- [ ] Seam A tests, in the style of `device-certificate-revocation.test.ts`.
