# 04: One way to provide a CSR everywhere: the Key step, the Key and CSR card, and a two-column Tools page

**What to build:** Replace the embedded generator (tickets 02 and 03) with one component, `KeySource` (`web/src/components/csr-key-source.tsx`), offering three ways to provide the CSR: generate it here, run an openssl command, or paste one. A pasted CSR is read in the browser (`web/src/lib/csr-inspect.ts`) and checked at once against the names and key algorithm asked for; where the form allows it, its key type is taken and its names can replace the form's.

- New Managed Certificate dialog: the "Subject" step becomes "Key and CSR", followed, when the key is generated here, by a "Save your key" step that keeps Next off until the key is downloaded or copied and the user says it is stored. Closing the dialog with an unsaved key asks first.
- Managed Certificate Overview: a "Key and CSR" card replaces the Name Change form and the Renewal CSR upload. "Replace key" uploads a CSR for a new key and can renew at once; "Change names" (or "Propose a name change") shows what changes and takes a CSR for the new names, with the validity for a Private CA. The pending name change and its withdrawal stay in the Identity card.
- CSR Generator page: two columns, what to ask for on the left, and on the right what the CSR will hold as it is typed, the openssl equivalent, then the key and the CSR.

**Blocked by:** none

**Status:** done

Supersedes 03. Decided by a UI prototype: the variants it compared are on the branch `prototype/csr-ux` (dialog B, details B and Tools B were chosen; a "give the CSR after approval" option for Proposals was tried and rejected).

- [x] A pasted CSR's key algorithm and names, as the web reads them, are what `parseCsr` reads (server/test/csr-generator.test.ts).
- [x] The openssl command makes a key and a CSR `parseCsr` accepts with exactly the names (server/test/csr-generator.test.ts).
- [x] The CSR reader imports nothing that could send a CSR anywhere.
- [x] A generated key that has not been saved is guarded on closing the dialog or sheet and on leaving the page.

## Comments
