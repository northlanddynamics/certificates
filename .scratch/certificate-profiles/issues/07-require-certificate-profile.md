# 07: Require proposing through a Certificate Profile

**What to build:** An Organization Administrator turns on a setting that has every non-administrator propose new Managed Certificates only through a Certificate Profile. Free-form Proposals are refused for them, including through their API keys, and "Custom" disappears from their dialog.

**Blocked by:** 02

**Status:** done

- [x] A new Organization setting, off by default, changed with `certificateProfile.update`. Changing it writes an Audit Event.
- [x] When on, a create request without a profile id from a caller lacking `managedCertificate.create` is refused with 403. That includes their API keys and an Organization's API key without `create`.
- [x] Organization Administrators, and anyone with `managedCertificate.create`, are unaffected.
- [x] Name Changes on existing Managed Certificates, with or without a profile, are unaffected.
- [x] The caller can tell whether free-form proposing is open to them (from `/api/me` or the profile list). The dialog offers "Custom" only then.
- [x] Server tests through the harness, including an API key, and a web test that "Custom" is hidden.

## Comments

- The setting is its own resource, `GET`/`PUT /api/organizations/{orgId}/certificate-profile-settings` (`{ requireProfile }`), read with `certificateProfile.read` and changed with `certificateProfile.update`; a change writes `certificate_profile_settings.changed`. The Certificate Profiles page has it.
- The create-Managed-Certificate route now takes a user's API key, which may do what both its person may now and it carries; a create or proposal made with one is also an `api_key.used`. An Organization's key is refused with 403: it acts as no one, so nobody would propose or own what it made.
- `/api/me` reports `requestsWithoutProfile` per Organization. A user's key made before its person was given `managedCertificate.create` does not carry it, so it is still held to the setting even where `/api/me` says the person is not.
- With the setting on and no enabled profile, the dialog's profile step says none is available and offers no way past it.
