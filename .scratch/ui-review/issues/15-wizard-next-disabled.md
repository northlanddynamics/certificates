# 15: Wizards disable Next without saying why

**What to build:** In the New Private CA wizard, Next is greyed out on Issuing CA (empty Subject) and Permitted names (none given) with nothing saying what is missing. Same in New Managed Certificate (Key and CSR, Save your key) and the CSR Generator's "Generate key and CSR". Tell the user what to do.

**Blocked by:** none

**Status:** ready-for-agent

- [ ] `components/stepped-form.tsx` lets each step give a reason it is incomplete; Next stays enabled and, on click, shows the reason by the field and focuses it.
- [ ] Or, if Next stays disabled, a tooltip and a line above the footer give the reason.
- [ ] Applied to every stepped form and the CSR Generator.
