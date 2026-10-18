# 06: ML-DSA in the CSR Generator

**What to build:** The CSR Generator makes ML-DSA-44, -65 and -87 keys and CSRs in the browser, natively where WebCrypto has ML-DSA and with `@noble/post-quantum` otherwise, and shows the equivalent OpenSSL command. See `spec.md`, "CSR Generator".

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] `web/src/lib/csr-generator.ts` offers the three algorithms; native WebCrypto is used when `generateKey` succeeds, otherwise noble, which is loaded only when an ML-DSA algorithm is chosen.
- [ ] Without native support the CSR is built from `@peculiar/asn1-csr`/`@peculiar/asn1-x509`; the key is exported as seed-form PKCS#8 PEM either way.
- [ ] The "Advanced" signature section hides for ML-DSA; the page shows the `openssl req -new -newkey ml-dsa-NN ...` command for the chosen names.
- [ ] The server test that runs the generator through `parseCsr` covers the three algorithms on the noble path and the native path.
- [ ] Whether `@noble/post-quantum` has been independently audited is recorded in the commit message.
- [ ] `CONTEXT.md`'s CSR Generator entry no longer says the key is always made with WebCrypto.
