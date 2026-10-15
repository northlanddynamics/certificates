# Private CA keys are held in a KMS

Amends [0002](0002-platform-never-holds-private-keys.md).

A Private CA must sign, so the platform needs a CA signing key, which ADR 0002 says it never holds. It holds one only as a non-exportable key in a KMS or HSM: the platform asks the KMS to sign a digest and gets back a signature, and in production it never has the key's material itself. The `Kms` interface (`server/src/kms.ts`) makes a signing key of a given algorithm (ECDSA P-256 or P-384, RSA 2048, 3072 or 4096) for a context, gives its public key and signs a digest with it; the platform stores only the opaque reference it returns. A contract test (`server/test/kms-signing-contract.ts`) states what every implementation keeps.

- **Production.** Keys live in the platform's own KMS account, one key per CA (the platform-made root and its Issuing CA each have their own), with the Organization's id bound in the key's policy or encryption context, so that one Organization's CA key can never sign for another. AWS KMS and Azure Key Vault plug in behind the interface. A key in the Organization's own cloud account (BYOK/HYOK) is a later implementation behind the same seam. Keys are only ever generated in the KMS, never imported.
- **Development and tests.** The local implementation, like `createLocalKms` for data keys, makes a software key and keeps it wrapped under its master key, bound to the key's algorithm and context, and refuses it under any other context. It never returns the key, but it is software: the platform's KMS configuration decides which implementation runs, and production must not run the local one.
- **Managed Certificate and device keys are unchanged.** The platform still never generates, stores or relays one; ADR 0002 holds for them.

We chose a KMS over holding CA keys as Secrets (wrapped by the Organization's data key), which would have been simpler and needed no new cloud service, because a CA key is worth far more than any other secret the platform holds: whoever has it can issue certificates every device and server in the Organization trusts. With a KMS a breach of the platform's database or servers exposes no CA key, and the KMS's own audit log records every signature. The interface signs digests rather than messages because a KMS limits what it will hash for you (AWS KMS takes at most 4 KB), and a CRL can be larger.

## The SCEP RA key exception

Device enrollment (SCEP) needs one key the platform holds as software: each Enrollment Profile's RA key.

- It is an RSA key the platform generates and wraps under the Organization's data key, like a Secret.
- It is software because SCEP clients commonly encrypt to it with PKCS#1 v1.5, which AWS KMS cannot decrypt (its RSA decryption is OAEP only).
- It only decrypts enrollment envelopes and signs SCEP responses. Its leak would expose CSRs and the one-time challenges in them, never a device or CA key.
- Its certificate is issued by the profile's Issuing CA, with no CA rights and only the key usage and EKU an SCEP RA certificate needs.

Consequences: production needs a KMS with asymmetric signing before a Private CA can be used there, and every CA signature is a call to it. Holding the RA key in a KMS is left for later.
