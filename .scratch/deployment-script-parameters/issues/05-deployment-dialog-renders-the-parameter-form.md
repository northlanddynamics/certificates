# 05: Deployment dialog renders the parameter form

**What to build:** In the new Deployment dialog, choosing a script version shows one text input for each parameter it declares: the label (falling back to the name), the description as help text, a required marker and the default pre-filled. Switching version keeps values for names that still exist. Submit sends `parameters`; the form checks required fields first and the server remains the authority. Uses the existing form components.

**Blocked by:** 01 (Declare parameters in a Deployment Script), 02 (Create a Deployment with parameter values).

**Status:** ready-for-agent

- [ ] A version with no parameters shows the dialog as today
- [ ] A version with parameters shows one input each, with label, help text, required marker and default
- [ ] Switching version keeps values for names present in both
- [ ] A required input left blank blocks submit; a server `400` is shown against the field at fault
- [ ] Created through the dialog, the Deployment's script receives the values
- [ ] Checked by hand in the app (no web test runner)

## Comments

- Implemented in `web/src/components/parameter-fields.tsx` (shared with ticket 06) and `web/src/pages/new-deployment-dialog.tsx`. A cleared field with a default sends blank, so the server applies the default, matching `parameterValues` on the server; the default shows as the placeholder. A `400` naming a declared parameter returns to the Script step with the problem shown against that field. Typecheck, CI and the hand check in the app are left to the PR: this environment cannot run them.
