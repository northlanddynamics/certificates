# 18: Key and CSR step has two primary buttons

**What to build:** "Generate here" shows a filled "Generate key and CSR" button and a filled Next, and Next is disabled until the first is pressed. Make it one action.

**Blocked by:** 15

**Status:** needs-triage

- [ ] Decide: Next generates the key when none exists yet, or the generate button stays and Next explains (ticket 15).
- [ ] Regenerating after a key exists asks first, since the saved key would no longer match.
