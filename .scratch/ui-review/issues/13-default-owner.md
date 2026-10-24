# 13: The New Managed Certificate wizard leaves it with no Owners

**What to build:** The Ownership step (`pages/new-managed-certificate-dialog.tsx:129`) starts with nobody ticked, so an Administrator ends up with "No Owners" while the key is described as "held by its Owners". Pre-select the creator.

**Blocked by:** none

**Status:** ready-for-agent

- [ ] `owners` starts with the signed-in user's key; they can untick it.
- [ ] Review warns when Key Custody is Owners and nobody is an Owner.
- [ ] On Overview, the Owners picker adds on select (drop the separate Add button).
