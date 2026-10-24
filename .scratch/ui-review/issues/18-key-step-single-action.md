# 18: Key and CSR step has two primary buttons

**What to build:** "Generate here" shows a filled "Generate key and CSR" button and a filled Next, and Next is disabled until the first is pressed. Make it one action.

**Blocked by:** 15

**Status:** done

- [x] Decide: Next generates the key when none exists yet, or the generate button stays and Next explains (ticket 15).
- [x] Regenerating after a key exists asks first, since the saved key would no longer match.

## Comments

Decided: Next generates the key when none exists yet (`resolve` on `SteppedForm`/`useSteps`, `withNewKey` in `csr-key-source.tsx`). Once a key exists, making a new one (after the names or key type change) is a button on the step that asks first, in the Key change sheet too.
