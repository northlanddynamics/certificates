# 06: Edit values from the Deployment page

**What to build:** The Deployment's page shows its stored parameter values and a control to replace them, using the same fields as the dialog, validated by the server against the pinned version. Shown only to a caller who holds `deployment:update`, checked through the permissions `/api/me` reports and not a role name.

**Blocked by:** 04 (Edit a Deployment's parameter values), 05 (Deployment dialog renders the parameter form).

**Status:** ready-for-agent

- [ ] The page lists the Deployment's values; a Deployment with no parameters shows no section
- [ ] The edit control saves through the edit route and shows the server's validation errors against the fields at fault
- [ ] The control is hidden from a caller without `deployment:update`
- [ ] After a save, the next run uses the new values
- [ ] Checked by hand in the app (no web test runner)
