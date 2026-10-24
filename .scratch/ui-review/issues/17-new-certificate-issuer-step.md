# 17: New Managed Certificate defaults to an issuer that cannot issue

**What to build:** Step 1 selects Let's Encrypt Staging even when the Organization has no ACME Account, and shows a red warning telling an Administrator to ask an Administrator, with no link. A ready Private CA is below the fold.

**Blocked by:** none

**Status:** ready-for-agent

- [ ] The default is the first issuer that can issue (has an ACME Account, or is an active Issuing CA); none when nothing can.
- [ ] An ACME CA with no account is shown but not selectable, with "Register an account" linking to ACME accounts for those who may, and "Ask an Organization Administrator" for the rest.
- [ ] The warning is an amber notice, not red error text.
