# 09: ML-DSA in the CSR Generator

**What to build:** An Owner who keeps their own key makes an ML-DSA-44, -65 or -87 key and CSR in the CSR Generator. The Generator uses the browser's own WebCrypto ML-DSA where it has it and `@noble/post-quantum` otherwise. It offers the key as a PKCS#8 PEM file, and shows the OpenSSL command that makes the same CSR. The key never leaves the browser (ADR 0002). See `spec.md`, "CSR Generator".

**Blocked by:** 03

**Status:** done

- [x] The Generator offers the three ML-DSA algorithms, locked as for any other algorithm where a flow fixes it.
- [x] Native WebCrypto is used when generating an ML-DSA key succeeds; otherwise noble is used, loaded only once an ML-DSA algorithm is chosen.
- [x] Without native support, the CSR is built from the ASN.1 CSR and X.509 schema packages in the same shape as the Agent's. In both paths the key is offered as unencrypted seed-form PKCS#8 PEM.
- [x] The signature hash choice hides for ML-DSA.
- [x] The page shows the equivalent OpenSSL 3.5 command for the chosen names.
- [x] The Generator's test through the real CSR parser covers the three algorithms on both the noble path (forced) and the native path, and checks the key re-imports from its seed.
- [x] Whether `@noble/post-quantum` has been independently audited is recorded in the commit message.
- [x] The glossary's CSR Generator entry no longer says the key is always made with WebCrypto.

## Comments

- The Generator is `web/src/lib/csr-generator.ts`; the noble path is `web/src/lib/csr-ml-dsa.ts`, built as its own chunk and imported only when an ML-DSA key is made. The native path is tried by generating the key, and noble is used if that fails or the native export is not the seed form, so the key file is always the seed-form PKCS#8.
- The hash choice and its Advanced section are hidden for ML-DSA in `web/src/pages/csr-tools.tsx`; the OpenSSL command was already offered for ML-DSA by `opensslCommand`. `KeySource` no longer forces ML-DSA into the command mode, and where a form fixes the algorithm it stays locked as before.
- Tests are in `server/test/csr-generator.test.ts`: the real CSR parser over each algorithm on the forced noble path and the native path, the key signing what the CSR's key verifies, the fallback when WebCrypto cannot make an ML-DSA key, and, where OpenSSL is 3.5 or later, OpenSSL reading both files and running the displayed command.
- `@noble/post-quantum` is not independently audited (its README says it was self-audited at 0.6.1, April 2026); this is recorded in the commit message of `97beeea`.
