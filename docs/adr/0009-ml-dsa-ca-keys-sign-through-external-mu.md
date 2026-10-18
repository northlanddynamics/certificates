# ML-DSA CA keys sign through the external μ

Amends [0007](0007-private-ca-keys-are-held-in-a-kms.md).

A Private CA can have ML-DSA-65 or ML-DSA-87 keys (FIPS 204, named in X.509 by RFC 9881), held in the KMS like any other CA key: non-exportable, one per CA, bound to the Organization. The KMS makes no ML-DSA-44 signing key, as a CA key outlives and outweighs any leaf. ADR 0007's seam signs a digest made with one hash per algorithm, but pure ML-DSA signs the whole message, and a KMS limits the message it takes (AWS KMS to 4 KB), which a large CRL outgrows. So for an ML-DSA key the platform computes the *external μ*, FIPS 204's 64-byte message representative, and the KMS signs that:

```
tr = SHAKE256(publicKey, 64 bytes)
μ  = SHAKE256(tr ‖ 0x00 ‖ 0x00 ‖ message, 64 bytes)   // pure ML-DSA, empty context
```

The signature is an ordinary pure ML-DSA signature over the whole message, which anyone verifies with the public key alone. The KMS returns it raw, as X.509 carries it, so nothing converts it. `externalMu` in `server/src/platform/crypto/kms.ts` computes μ; the KMS signing contract (`server/test/support/kms-signing-contract.ts`) checks each ML-DSA key's signature with WebCrypto as pure ML-DSA, over a message larger than 4 KB too.

- **Development and tests.** The local KMS makes the key with Bun's own ML-DSA and keeps it wrapped under its master key, bound to its algorithm and Organization, as ADR 0007 says for every key. Bun exports it in the 32-byte seed form. Node's crypto signs only a whole message, so the local KMS signs μ with `@noble/post-quantum`'s internal signing with an external μ, from that seed.
- **AWS KMS.** Its `Sign` takes μ as `MessageType: EXTERNAL_MU`, a 64-byte message, with the `ML_DSA_SHAKE_256` signing algorithm, and documents it for messages over 4 KB. `RAW` would limit an ML-DSA message to 4 KB.
- **Google Cloud KMS.** It has ML-DSA-44, -65 and -87 keys, and signs μ only with a key made for it: the `PQ_SIGN_ML_DSA_65_EXTERNAL_MU` and `PQ_SIGN_ML_DSA_87_EXTERNAL_MU` algorithms. Its implementation makes its ML-DSA keys with those.
- **Azure Key Vault.** It has no ML-DSA keys (in Key Vault or Managed HSM), so where it is the platform's KMS, ML-DSA is refused for a new Private CA with a reason.

We chose μ over signing the message in the KMS, which would need no hashing on our side, because the message size limit would stop a large CRL from being reissued, and so stop a Revocation. We chose it over HashML-DSA, which also signs a digest, because HashML-DSA is a different signature algorithm, with its own OIDs, that RFC 9881 does not use for X.509 and that clients verifying pure ML-DSA reject.

Consequences: what is signed is computed with the key's public key, so the platform reads it from the KMS before signing. The AWS and Google behaviour above was checked against their documentation through search results in October 2026, the pages themselves being unreachable from where this was written, so whoever builds either implementation confirms it against the pages and runs the signing contract unchanged against the service.
