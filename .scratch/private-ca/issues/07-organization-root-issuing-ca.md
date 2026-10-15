# 07: Organization-root Issuing CA

**What to build:** An Organization Administrator creates an Issuing CA whose key is in the KMS but whose certificate is signed by the Organization's own (often offline) root: they download its CSR, sign it elsewhere, and upload the result and the chain above it. See `spec.md`, "Solution" and user stories 2 to 5 and 12.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Creating a Private CA of the Organization-root kind makes only an Issuing CA key in the KMS, leaves the Private CA `awaiting_signature`, and offers its CSR for download.
- [ ] Uploading the signed certificate and its chain is refused when the certificate is not for the CSR's key, is not a CA certificate, or the chain does not verify; when accepted the Private CA becomes `active` (`private_ca.csr_signed` Audit Event).
- [ ] Issuance from a Private CA that is `awaiting_signature` is refused.
- [ ] The platform enforces the permitted name rules for it, and shows any name constraints the Organization's root put in the Issuing CA.
- [ ] Web: the CSR download and upload steps on the Private CA page.
