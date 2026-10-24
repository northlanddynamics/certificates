# 06: Certificate authorities folds over a single item

**What to build:** In the sidebar, "Certificate authorities" expands to Private CAs alone, while ACME accounts sits under Integrations. Group the two CA pages together, or drop the fold.

**Blocked by:** none

**Status:** needs-triage

- [ ] Decide: Certificate authorities = Private CAs + ACME accounts (Integrations keeps DNS Providers), or a flat list.
- [ ] A section with one visible page renders as a plain item, not a fold (for roles that see only one).

## Comments

Suggested: Administration › Certificate authorities = Private CAs + ACME accounts (both are where certificates come from); Integrations = DNS Providers + Notification channels (ticket 05 put channels there). A section with one page the caller may open renders as a plain item. Waiting on a yes.
