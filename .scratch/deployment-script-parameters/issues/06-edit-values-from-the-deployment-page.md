# 06: Edit values from the Deployment page

**What to build:** The Deployment's page shows its stored parameter values and a control to replace them, using the same fields as the dialog, validated by the server against the pinned version. Shown only to a caller who holds `deployment:update`, checked through the permissions `/api/me` reports and not a role name.

**Blocked by:** 04 (Edit a Deployment's parameter values), 05 (Deployment dialog renders the parameter form).

**Status:** ready-for-agent

- [ ] The page lists the Deployment's values; a Deployment with no parameters shows no section
- [ ] The edit control saves through the edit route and shows the server's validation errors against the fields at fault
- [ ] The control is hidden from a caller without `deployment:update`
- [ ] After a save, the next run uses the new values
- [ ] Checked by hand in the app (no web test runner)

## Comments

- Implemented in `web/src/pages/deployments.tsx`: there is no page per Deployment, so each row of the Deployments page gets a "Parameters" dialog beside "Runs". It lists the values the pinned version declares (or "Not set"), and is absent when that version declares none. "Edit values" (shown only with `deployment:update` from `/api/me`) swaps in the dialog's `ParameterFields`, pre-filled with the stored values, and saves through `PUT .../deployments/{id}/parameters` (`api.setDeploymentParameters`); a `400` shows each refused value against its field. Typecheck, CI and the hand check in the app are left to the PR: this environment cannot run them.
