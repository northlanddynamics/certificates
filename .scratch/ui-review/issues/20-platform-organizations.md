# 20: Platform Organizations page is a bare form

**What to build:** The Operator's page lists Organizations as plain text ("Acme Corp (acme)") above a full-width create form with a full-width button, and nothing confirms an invitation was sent. Match the other list pages.

**Blocked by:** none

**Status:** needs-triage

- [ ] A data table: name, slug, created, members, pending invitation (and its email).
- [ ] "New Organization" opens a dialog with the three fields (slug follows the name, ticket 16).
- [ ] Success shows a toast naming the email invited; a pending invitation can be resent if the API allows (check; out of scope if it needs server work).
