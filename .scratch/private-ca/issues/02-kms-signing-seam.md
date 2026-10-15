# 02: KMS signing seam and ADR 0007

**What to build:** The KMS can create a non-exportable asymmetric signing key for an Organization, give its public key and sign with it, so that a Private CA's keys never exist outside the KMS in production. Only the local (development and test) implementation is built. ADR 0007 records the decision. See `spec.md`, "ADR 0007" and "KMS seam".

**Blocked by:** None (can start immediately)

**Status:** done

- [x] The `Kms` interface gains: create a signing key of a given algorithm (ECDSA P-256, P-384; RSA 2048, 3072, 4096) for a context (an Organization's id), returning an opaque key reference; get its public key; sign a digest.
- [x] The local implementation keeps the key wrapped under its master key, never returns private key material, and refuses to sign with a key under a different context than it was made for.
- [x] A contract test of these operations (create, public key, sign and verify with `@peculiar/x509`/WebCrypto, refusal across contexts) that a later AWS KMS or Azure Key Vault implementation can run unchanged.
- [x] ADR 0007 is written: CA signing keys only as non-exportable KMS/HSM keys, local software keys only for development and tests, keys in the platform's KMS per CA scoped to the Organization, BYOK/HYOK as a later implementation; and the SCEP RA key exception (a wrapped software key, because SCEP clients use PKCS#1 v1.5 and AWS KMS decrypts only OAEP; it decrypts enrollment envelopes and signs SCEP responses only). It amends ADR 0002, which gains a pointer to it.
