# 07: Require proposing through a Certificate Profile

**What to build:** An Organization Administrator turns on a setting that has every non-administrator propose new Managed Certificates only through a Certificate Profile. Free-form Proposals are refused for them, including through their API keys, and "Custom" disappears from their dialog.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] A new Organization setting, off by default, changed with `certificateProfile.update`. Changing it writes an Audit Event.
- [ ] When on, a create request without a profile id from a caller lacking `managedCertificate.create` is refused with 403. That includes their API keys and an Organization's API key without `create`.
- [ ] Organization Administrators, and anyone with `managedCertificate.create`, are unaffected.
- [ ] Name Changes on existing Managed Certificates, with or without a profile, are unaffected.
- [ ] The caller can tell whether free-form proposing is open to them (from `/api/me` or the profile list). The dialog offers "Custom" only then.
- [ ] Server tests through the harness, including an API key, and a web test that "Custom" is hidden.
