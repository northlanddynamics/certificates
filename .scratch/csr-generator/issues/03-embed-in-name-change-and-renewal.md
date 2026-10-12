# 03: Generate the CSR for a Name Change and a Renewal upload

**What to build:** The Name Change form (`web/src/pages/name-change-controls.tsx`) and the Renewal CSR upload (`web/src/pages/renewal-controls.tsx`) embed the CSR Generator as ticket 02 does the creation dialog. In a Name Change the names are the new ones typed on the form; in a Renewal upload they are the Managed Certificate's current names. In both, the key algorithm is the Managed Certificate's own and locked. The pasted-CSR warning from ticket 02 shows on both textareas.

**Blocked by:** 02 (Generate the CSR inside the new Managed Certificate dialog)

**Status:** ready-for-agent

- [ ] The Name Change form's embedded generator follows the new names as they are typed, locked to the Managed Certificate's key algorithm, and "Use this CSR" fills the form's CSR textarea once the key is saved.
- [ ] The Renewal upload's embedded generator uses the current names and the Managed Certificate's key algorithm, and its CSR fills the upload textarea.
- [ ] The pasted-CSR warning shows on both textareas and never blocks.
- [ ] A CSR made this way is accepted by the existing name-change and CSR-upload routes.
- [ ] The paste path is unchanged on both.

## Comments
