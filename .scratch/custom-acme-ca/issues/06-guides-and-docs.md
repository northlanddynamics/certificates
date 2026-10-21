# 06: Guides and docs for custom ACME CAs

**What to build:** The in-app guides and `docs/` explain custom ACME CAs: adding one, External Account Binding, the environment tag, what is fixed after creation, and that deletion is blocked while a Certificate refers to the CA.

**Blocked by:** 04, 05

**Status:** ready-for-agent

- [ ] The in-app guides and `docs/` use the glossary's terms (ACME CA, ACME Account, environment tag) and agree with each other.
- [ ] The setup guide's ACME account step covers the built-in and the custom path.
- [ ] The existing guide tests still pass, extended if they assert the changed text.
