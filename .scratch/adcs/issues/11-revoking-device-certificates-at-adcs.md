# 11: Revoking Device Certificates at ADCS

**What to build:** Device Certificates from an ADCS CA are revoked at ADCS in three ways: by an Organization Administrator, by the Enrollment Validator's revocation feed (such as Intune retiring a device), and as `superseded` once the replacement a RenewalReq asked for is issued. Each is recorded only once ADCS confirms, and the device list shows "Revoked" and the CDP URLs. See `.scratch/adcs/spec.md` (Revocation).

**Blocked by:** 08 (Revoking at ADCS), 10 (ADCS-backed Enrollment Profiles over SCEP).

**Status:** done

- [x] Manual revocation of a Device Certificate from ADCS goes through `adcs.revoke` and is recorded on confirmation.
- [x] The revocation feed revokes at ADCS, and reports each outcome back to the Enrollment Validator only once ADCS has answered.
- [x] RenewalReq's `superseded` revocation happens only after the replacement is issued and ADCS confirms.
- [x] A refused or unreachable revocation is reported and retried as the feed's rules already say.
- [x] Seam A tests, in the style of `device-certificate-revocation.test.ts`.

## Comments

Implemented.
- Manual: the Device Certificate revocation API already reached ADCS through `adcs.revoke` (ticket 02's Revocation Requests). Device Certificates now show `issuerKind` and `crlDistributionPoints` (read from the leaf); the web side sheet lists the CDP URLs and offers ADCS's reasons (no `privilegeWithdrawn`, 422 from the API).
- Feed (`enrollment-validators.ts`): a pulled Revocation that an ADCS CA confirms later is kept, marked `asked_at`, and answered on the first pass after ADCS answered. A failed one counts as a try and is asked again on the next pass, answered `failed` with the CA's message at the fifth try, the same count as a change that rolls back (which is how "no Agent online" counts). A matched Device Certificate whose revocation someone else already asked for waits for that too.
- Superseded (`device-enrollment.ts`): the renewed Device Certificate records `superseded_by` (the replacement's serial) on the change that stores the replacement, and a RenewalReq signed with it is refused from then on. A new pass (`supersedeRenewed`, every 15 minutes) asks again for those not revoked: at once when no Agent could be asked, and a day after a failed request, until they expire.
- Migration 0066 adds both columns and a partial index for the pass.
