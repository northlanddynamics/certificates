# 06: Guides and docs for custom ACME CAs

**What to build:** The in-app guides and `docs/` explain custom ACME CAs: adding one, External Account Binding, the environment tag, what is fixed after creation, and that deletion is blocked while a Certificate refers to the CA.

**Blocked by:** 04, 05

**Status:** resolved

- [x] The in-app guides and `docs/` use the glossary's terms (ACME CA, ACME Account, environment tag) and agree with each other.
- [x] The setup guide's ACME account step covers the built-in and the custom path.
- [x] The existing guide tests still pass, extended if they assert the changed text.

## Comments

- The repo has no in-app setup guide and no `setup-guides-web.test.ts`; the in-app guidance is the ACME accounts page's own text, and `docs/` had no ACME guide. The guide is new, `docs/acme-cas.md`, linked from a new "ACME CAs" section of the README: the built-in ACME CAs, registering an ACME Account with a built-in or a custom one, adding a custom one (directory URL rules, registration in the same step), External Account Binding, the Environment Tag, what is fixed after creation, and why deletion is refused while a Managed Certificate or Certificate refers to it. The ACME accounts page now names the custom path beside the built-in one, the Managed Certificates list's "Environment" column and filter are "Environment tag", and the README's Secrets section names the External Account Binding HMAC key. `acme-ca-guide.test.ts` holds the guide's table of built-in ACME CAs to `BUILT_IN_ACME_CAS`. The test runs in the PR's CI: this environment cannot run the needed components.
