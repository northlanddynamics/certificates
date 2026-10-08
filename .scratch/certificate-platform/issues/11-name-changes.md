# 11: Name changes and pending Approval

**What to build:** An Owner can propose adding or removing names on an existing Managed Certificate, together with a new CSR covering the new names. The change waits for Approval while Renewal continues with the last approved names. Organization Administrators' changes apply immediately.

**Blocked by:** 06 (Approval), 09 (Renewal Policy and scheduler)

**Status:** ready-for-agent

- [ ] An Owner can propose a name change with a matching new CSR; at most one name change is pending at a time.
- [ ] While pending, Renewal continues with the last approved names and CSR.
- [ ] On approval, the next issuance uses the new names and CSR; on rejection, the change is discarded and the Managed Certificate is otherwise unaffected.
- [ ] Name changes by Organization Administrators need no Approval.
- [ ] Proposals and decisions are audited and appear in the history view.
