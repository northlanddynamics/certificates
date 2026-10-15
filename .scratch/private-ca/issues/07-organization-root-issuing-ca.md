# 07: Organization-root Issuing CA

**What to build:** An Organization Administrator creates an Issuing CA whose key is in the KMS but whose certificate is signed by the Organization's own (often offline) root: they download its CSR, sign it elsewhere, and upload the result and the chain above it. See `spec.md`, "Solution" and user stories 2 to 5 and 12.

**Blocked by:** 03, 10

Each Issuing CA under an Organization root gets its own key, CSR and upload step; the Private CA holds the uploaded root and chain once, shared by its Issuing CAs (see 10 and `spec.md`, "Adding an Issuing CA").

**Status:** ready-for-agent

- [ ] Creating a Private CA of the Organization-root kind makes only its first Issuing CA's key in the KMS, leaves that Issuing CA `awaiting_signature`, and offers its CSR for download. Adding another Issuing CA to it does the same for the new one.
- [ ] Uploading an Issuing CA's signed certificate is refused when it is not for the CSR's key, is not a CA certificate, or does not verify against the Private CA's root and chain; the root and chain are uploaded with the first Issuing CA and reused for later ones. When accepted the Issuing CA becomes `active` (`private_ca.csr_signed` Audit Event naming the Issuing CA).
- [ ] Issuance from an Issuing CA that is `awaiting_signature` is refused.
- [ ] The platform enforces each Issuing CA's permitted name rules, and shows any name constraints the Organization's root put in the Issuing CA.
- [ ] Web: the CSR download and upload steps on each Issuing CA's row of the Private CAs page.
