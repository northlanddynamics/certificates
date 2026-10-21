# 02: Create a custom ACME CA and register its account in one step

**What to build:** An Organization Administrator adds a custom ACME CA, gives it a name, an https directory URL, a contact email and an environment tag, and the platform registers the Organization's ACME Account with it in the same step. It then appears on the ACME accounts page and its account can be tested.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] Creating a custom CA registers the account with it in one operation; if the CA refuses, nothing is saved and the CA's reason is shown.
- [ ] Names are unique within the Organization; an Organization may have several custom CAs.
- [ ] A directory URL that is not https, or that is loopback or link-local (including the metadata address), is refused with a clear message; private ranges are allowed. The check also runs when the platform connects.
- [ ] The tag is `staging`, `production` or none.
- [ ] The CA appears on the ACME accounts page with its tag, and the Test button works for its account.
- [ ] `acmeAccount` `create` and `read` apply; a user who is not an Organization Administrator cannot see or create CAs.
- [ ] Creating the CA and registering the account each write an Audit Event.
- [ ] Server tests through the harness against Pebble cover success, refusal, URL rules, permissions and Audit Events.
