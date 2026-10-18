# 02: ML-DSA signing in the KMS seam, and its ADR

**What to build:** The KMS makes ML-DSA-65 and ML-DSA-87 signing keys bound to an Organization and signs with them through the external μ, so that a Private CA's ML-DSA keys can live in the KMS like any other CA key, and a CRL of any size can be signed. The local KMS implements it; a new ADR amends ADR 0007. See `spec.md`, "KMS seam".

**Blocked by:** 01

**Status:** done

From the prototype, what the platform computes before asking the KMS to sign:

```
tr = SHAKE256(publicKey, 64 bytes)
μ  = SHAKE256(tr ‖ 0x00 ‖ 0x00 ‖ message, 64 bytes)   // pure ML-DSA, empty context
```

- [x] The key algorithms gain `ml-dsa-44`, `ml-dsa-65` and `ml-dsa-87`; the KMS creates signing keys of the latter two.
- [x] The seam signs μ for ML-DSA keys and a digest for the rest; an ML-DSA signature is returned raw and verifies as pure ML-DSA over the whole message.
- [x] The local KMS makes the key with Bun's native ML-DSA, wraps it bound to its algorithm and Organization like every other key, and signs μ with `@noble/post-quantum`'s internal signing with external μ, from the key's seed.
- [x] The KMS signing contract covers ML-DSA-65 and ML-DSA-87: create, public key, sign and verify with WebCrypto, a message over 4 KB, and refusal under another Organization's context.
- [x] A new ADR, which ADR 0007 points to, records:
  - ML-DSA CA keys are signed through μ.
  - AWS KMS's `EXTERNAL_MU`, checked against AWS's documentation.
  - Google Cloud KMS's support, checked.
  - Azure Key Vault has no ML-DSA keys, so ML-DSA is refused for a Private CA where it is the KMS.

## Comments

- AWS's and Google's documentation sites were unreachable from the implementing session (network policy), so their ML-DSA support was checked through search results of those pages; ADR 0009 says so and asks whoever builds either implementation to confirm against the pages.
- Until ticket 03, the API takes only ECDSA and RSA for a new Private CA, Managed Certificate or Deployment (`CLASSICAL_KEY_ALGORITHMS`), and the CA module refuses to sign with an ML-DSA key.
