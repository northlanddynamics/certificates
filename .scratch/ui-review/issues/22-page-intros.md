# 22: Page intros are walls of text

**What to build:** Private CAs, Agents, Deployments, ACME accounts and Certificate Profiles open with three or four lines of dense prose. Keep one sentence; fold the rest into "How it works", as Certificate Profiles already does.

**Blocked by:** none

**Status:** ready-for-agent

- [ ] A shared page header component: title, one-line description, primary action, optional collapsible "How it works".
- [ ] Every page uses it, which also fixes the inconsistent title-to-description gap (CSR Generator and PEM Parser are tight, others loose).
