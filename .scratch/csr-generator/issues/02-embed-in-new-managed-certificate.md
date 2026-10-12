# 02: Generate the CSR inside the new Managed Certificate dialog

**What to build:** The new Managed Certificate dialog (`web/src/pages/new-managed-certificate-dialog.tsx`) embeds the CSR Generator next to its CSR textarea. It uses the names and key algorithm already on the form, locked, and fills the textarea with the CSR it makes. Pasting a CSR still works. A pasted CSR signed with SHA-1, MD5 or RSA-PSS gets a non-blocking warning.

**Blocked by:** 01 (CSR Generator and the Tools page)

**Status:** ready-for-agent

- [x] The embedded generator takes the form's names and key algorithm and shows them read-only; the form's own validation stays the source of those values, and changing them clears a CSR already generated.
- [x] "Use this CSR" fills the form's CSR textarea and is disabled until the key has been downloaded or copied.
- [x] A shared warning component decodes only the signature algorithm of the pasted PEM with `@peculiar/x509` and, for SHA-1, MD5 or RSA-PSS, says the CA is likely to refuse it. It never blocks the submit and shows nothing else about the CSR.
- [x] A CSR made this way is accepted by the existing create route, including for a wildcard name and a Proposal that waits for Approval.
- [x] The paste path is unchanged.

## Comments

Implemented in the commit "CSR Generator: embed it in the new Managed Certificate dialog". Not yet committed: `web/src/pages/new-managed-certificate-dialog.tsx` carries the change that embeds the generator, but the file itself is untracked (it belongs to the still uncommitted sidebar rework, with the `ui/` components it imports), so it goes in with that work.

- The generator takes `onUse`; given it, it renders no `<form>` of its own (it sits inside the dialog's form) and Enter in its inputs does not submit the outer form. "Use this CSR" is disabled until the key is downloaded or copied.
- Changing the names or key algorithm clears the generated CSR, and also the textarea if it still holds that generated CSR. A CSR the user pasted or edited is left alone.
- `weakSignatureWarning` (`web/src/lib/csr-signature.ts`) and `CsrSignatureWarning` (`web/src/components/csr-signature-warning.tsx`) are the shared warning for ticket 03. MD5 is not named by `@peculiar/x509`; it comes back as its OID, which the module matches.
- Checked in the browser pane through a temporary harness page mounting the real dialog: locked names and algorithm, "Use this CSR" disabled until the key was downloaded (the pane refuses clipboard writes, so Copy was not exercised), CSR filled in, cleared on a name change, SHA-1 paste warns.
- Server tests: a generated CSR for a wildcard and its base name is created and issued; a generated CSR for a wildcard is proposed and waits for Approval.
