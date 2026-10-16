# 07: Organization-root Issuing CA

**What to build:** An Organization Administrator creates an Issuing CA whose key is in the KMS but whose certificate is signed by the Organization's own (often offline) root: they download its CSR, sign it elsewhere, and upload the result and the chain above it. See `spec.md`, "Solution" and user stories 2 to 5 and 12.

**Blocked by:** 03, 10

Each Issuing CA under an Organization root gets its own key, CSR and upload step; the Private CA holds the uploaded root and chain once, shared by its Issuing CAs (see 10 and `spec.md`, "Adding an Issuing CA").

**Status:** done

- [x] Creating a Private CA of the Organization-root kind makes only its first Issuing CA's key in the KMS, leaves that Issuing CA `awaiting_signature`, and offers its CSR for download. Adding another Issuing CA to it does the same for the new one.
- [x] Uploading an Issuing CA's signed certificate is refused when it is not for the CSR's key, is not a CA certificate, or does not verify against the Private CA's root and chain; the root and chain are uploaded with the first Issuing CA and reused for later ones. When accepted the Issuing CA becomes `active` (`private_ca.csr_signed` Audit Event naming the Issuing CA).
- [x] Issuance from an Issuing CA that is `awaiting_signature` is refused.
- [x] The platform enforces each Issuing CA's permitted name rules, and shows any name constraints the Organization's root put in the Issuing CA.
- [x] Web: the CSR download and upload steps on each Issuing CA's row of the Private CAs page.

## Comments

> *Implemented by AI (`claude/private-ca-7`).*

Notes from the implementation:
- `POST /private-cas` takes `kind` (`platform_root` by default, or `organization_root`). Under an Organization root, `lifetimeYears` is refused with 422 when creating the Private CA or adding an Issuing CA, because the Organization's root decides how long an Issuing CA lasts.
- `GET …/issuing-cas/{id}/csr` serves the CSR (PEM, `application/pkcs10`). It is signed again by the KMS key on each download and asks for a CA with pathLen 0. It needs `privateCa.update`, and returns 422 for a platform-made Issuing CA.
- `POST …/issuing-cas/{id}/certificate` takes `{ certificate, root?, chain? }` (PEM). The first Issuing CA signed must send `root`, and the Private CA keeps that root and `chain` (new column `private_ca.chain_pem`, migration 0037) for its other Issuing CAs. A later upload may send the same root and chain again, but a different one is refused with 422. Besides the checks the ticket asks for, an upload is also refused when the certificate's subject differs from the CSR's, or when it or anything above it has expired.
- An upload is also refused under a revoked root, or when the certificate is not valid yet. The path check covers signatures, CA flags and validity only. It does not check path length constraints or name constraints set by the root or chain.
- Issuance clips each Certificate to the end of the Issuing CA and of everything above it. An Organization's root may have signed the Issuing CA for longer than the root itself lasts.
- An accepted upload publishes the Issuing CA's CRL straight away, in the same Unit of Work as `private_ca.csr_signed`.
- Each Issuing CA in the response now has `nameConstraints` (`{ permitted, excluded }`, entries such as `dns:example.com` or `ip:10.0.0.0/8`), read from its certificate. It is `null` when there are none. The web shows them only for Organization-root Issuing CAs.
- Stored Certificate chains and the Issuing CA's chain download include any intermediates between the Issuing CA and the Organization root.
- The Managed Certificate forms already listed only `active` Issuing CAs, so they needed no change.

