# 05: Request through a Certificate Profile in the portal

**What to build:** A portal user requests a Managed Certificate in four steps: what it's for (the enabled Certificate Profiles, in plain words), the names (checked against the profile's name rules as they type), the key (made in the browser with the profile's key algorithm and offered for download, or a pasted CSR), and a review before submitting. The result is a Proposal, or a Managed Certificate created outright for those who may create one, exactly as the Console makes it. A user with no enabled profile to request through is told so and where to get help.

**Blocked by:** 03 (Sessions land in their front end)

**Status:** ready-for-agent

- [ ] Built on the existing Certificate Profile and Managed Certificate endpoints; no new server behaviour.
- [ ] Only Certificate Profiles are offered; there is no request without one in the portal.
- [ ] Each profile shows its name and description, and whether requests need Approval.
- [ ] Names are checked as the user types, by the same name rules the server applies, and the step cannot continue while one is refused.
- [ ] The key step uses the CSR Generator with the profile's key algorithm preset (a choice only when the profile allows several). The private key is offered to download or copy and never sent; the user confirms they saved it. A pasted or dropped CSR is accepted instead.
- [ ] The review shows the profile, names, Owners (the requester and any profile Team) and Renewal Policy, then submits.
- [ ] After submitting, the user sees the Proposal waiting for Approval, or the new Managed Certificate.
- [ ] With no enabled profile, the step says so and links to the Organization's help.
- [ ] Works at phone width.
