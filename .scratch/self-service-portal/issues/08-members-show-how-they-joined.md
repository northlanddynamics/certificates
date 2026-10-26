# 08: Members page shows how each member joined

**What to build:** On the Members page, an Organization Administrator sees how each member joined: by invitation (and who invited them), or by first sign-in through an SSO Connection (and which one). They can tell self-service members from invited ones, and give a self-service Member a higher role there; there is no need to invite someone who is already a member.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The members listing reports, for each member, how they joined, from the existing `member.provisioned` and invitation Audit Events, or from a stored field if reading the audit log there is too slow.
- [ ] The Members page shows it in its own column.
- [ ] Changing the role of a member who joined through SSO works as for any member, through the existing organization endpoints and their rules.
- [ ] Harness tests cover a member who joined by invitation and one who joined through a connection.
