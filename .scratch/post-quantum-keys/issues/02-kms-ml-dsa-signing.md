# 02: ML-DSA signing in the KMS seam, and its ADR

**What to build:** The `Kms` seam creates ML-DSA-65 and ML-DSA-87 signing keys and signs an ML-DSA external μ, implemented by the local KMS; a new ADR amends ADR 0007. See `spec.md`, "KMS signing".

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] `KeyAlgorithm` gains `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`; `createSigningKey` accepts only the latter two for CA keys.
- [ ] A helper computes μ from a public key and a message; the seam signs μ for ML-DSA keys and a digest for the rest. The resulting signature verifies as pure ML-DSA over the whole message with WebCrypto.
- [ ] The local KMS generates the key with Bun's native ML-DSA, wrapped and context-bound as for the other algorithms, and signs μ with `@noble/post-quantum` (`internal.sign` with `externalMu: true`) from the key's seed, since `node:crypto` cannot sign μ.
- [ ] The KMS contract test covers ML-DSA, including a message over 4 KB.
- [ ] A new ADR records: ML-DSA CA keys are signed through μ; AWS KMS `EXTERNAL_MU` (checked against AWS's documentation), Google Cloud KMS (checked), Azure Key Vault (no ML-DSA keys: such Organizations cannot have an ML-DSA Private CA). ADR 0007 gains a pointer to it.
