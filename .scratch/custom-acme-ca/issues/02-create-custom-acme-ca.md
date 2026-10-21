# 02: Create a custom ACME CA and register its account in one step

**What to build:** An Organization Administrator adds a custom ACME CA, gives it a name, an https directory URL, a contact email and an environment tag, and the platform registers the Organization's ACME Account with it in the same step. It then appears on the ACME accounts page and its account can be tested.

**Blocked by:** 01

**Status:** resolved

- [x] Creating a custom CA registers the account with it in one operation; if the CA refuses, nothing is saved and the CA's reason is shown.
- [x] Names are unique within the Organization; an Organization may have several custom CAs.
- [x] A directory URL that is not https, or that is loopback or link-local (including the metadata address), is refused with a clear message; private ranges are allowed. The check also runs when the platform connects.
- [x] The tag is `staging`, `production` or none.
- [x] The CA appears on the ACME accounts page with its tag, and the Test button works for its account.
- [x] `acmeAccount` `create` and `read` apply; a user who is not an Organization Administrator cannot see or create CAs.
- [x] Creating the CA and registering the account each write an Audit Event.
- [x] Server tests through the harness against Pebble cover success, refusal, URL rules, permissions and Audit Events.

## Comments

- `POST /api/organizations/{orgId}/acme-cas` adds the CA (`acme_ca`, migration 0049) and registers its account in one `UnitOfWork` change, writing `acme_ca.created` and `acme_account.created`. The account is registered at the CA first, so a refusal (422, with the CA's reason) or an unreachable CA (502) leaves nothing saved; a name taken is checked before the CA is asked (409).
- The directory URL rule (`server/src/issuance/acme/directory-url.ts`): https only (400), and no loopback, link-local, unspecified or metadata address, judged by every address the name resolves to (422). It runs inside the ACME client's connection check for every custom CA, so it applies on save and on every later connection. Tests exempt Pebble's own origin (`allowedDirectoryOrigins`), and reach Pebble by `127.0.0.1` and other names to show the rule, not the network, refuses them.
- Pebble cannot be told to refuse a registration without EAB (ticket 04), so the harness gains `registrationRefusal` to stand in for a CA that says no.
- Visibility: as for the built-ins, everyone in the Organization sees a custom CA's name and tag (the issuer picker in ticket 03 needs it); only Organization Administrators see its directory URL or add one.
- The inventory's `tag` filter also matches custom CAs.
