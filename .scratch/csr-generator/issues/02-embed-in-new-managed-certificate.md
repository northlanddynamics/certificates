# 02: Generate the CSR inside the new Managed Certificate dialog

**What to build:** The new Managed Certificate dialog (`web/src/pages/new-managed-certificate-dialog.tsx`) embeds the CSR Generator next to its CSR textarea. It uses the names and key algorithm already on the form, locked, and fills the textarea with the CSR it makes. Pasting a CSR still works. A pasted CSR signed with SHA-1, MD5 or RSA-PSS gets a non-blocking warning.

**Blocked by:** 01 (CSR Generator and the Tools page)

**Status:** ready-for-agent

- [ ] The embedded generator takes the form's names and key algorithm and shows them read-only; the form's own validation stays the source of those values, and changing them clears a CSR already generated.
- [ ] "Use this CSR" fills the form's CSR textarea and is disabled until the key has been downloaded or copied.
- [ ] A shared warning component decodes only the signature algorithm of the pasted PEM with `@peculiar/x509` and, for SHA-1, MD5 or RSA-PSS, says the CA is likely to refuse it. It never blocks the submit and shows nothing else about the CSR.
- [ ] A CSR made this way is accepted by the existing create route, including for a wildcard name and a Proposal that waits for Approval.
- [ ] The paste path is unchanged.

## Comments
