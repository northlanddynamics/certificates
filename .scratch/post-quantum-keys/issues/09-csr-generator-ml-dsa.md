# 09: ML-DSA in the CSR Generator

**What to build:** An Owner who keeps their own key makes an ML-DSA-44, -65 or -87 key and CSR in the CSR Generator. The Generator uses the browser's own WebCrypto ML-DSA where it has it and `@noble/post-quantum` otherwise. It offers the key as a PKCS#8 PEM file, and shows the OpenSSL command that makes the same CSR. The key never leaves the browser (ADR 0002). See `spec.md`, "CSR Generator".

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] The Generator offers the three ML-DSA algorithms, locked as for any other algorithm where a flow fixes it.
- [ ] Native WebCrypto is used when generating an ML-DSA key succeeds; otherwise noble is used, loaded only once an ML-DSA algorithm is chosen.
- [ ] Without native support, the CSR is built from the ASN.1 CSR and X.509 schema packages in the same shape as the Agent's. In both paths the key is offered as unencrypted seed-form PKCS#8 PEM.
- [ ] The signature hash choice hides for ML-DSA.
- [ ] The page shows the equivalent OpenSSL 3.5 command for the chosen names.
- [ ] The Generator's test through the real CSR parser covers the three algorithms on both the noble path (forced) and the native path, and checks the key re-imports from its seed.
- [ ] Whether `@noble/post-quantum` has been independently audited is recorded in the commit message.
- [ ] The glossary's CSR Generator entry no longer says the key is always made with WebCrypto.
