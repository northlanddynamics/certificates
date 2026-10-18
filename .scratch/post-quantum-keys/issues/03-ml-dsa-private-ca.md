# 03: ML-DSA Private CAs

**What to build:** An Organization Administrator creates a platform-made Private CA with key algorithm ML-DSA-65 or ML-DSA-87; its root, Issuing CAs, Certificates and CRLs are signed with ML-DSA. See `spec.md`, "Where each is allowed".

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] `private-ca.ts` accepts `ml-dsa-65` and `ml-dsa-87` for a Private CA; certificate and CRL signing use the RFC 9881 OID with parameters absent.
- [ ] An Organization's own root (`organization_root`) with an ML-DSA key is accepted when its Issuing CA's key is ML-DSA.
- [ ] `certificate-facts.ts` names ML-DSA signatures and keys.
- [ ] Tests: issue an ML-DSA Certificate and CRL and verify both with `@peculiar/x509`; Revocation reissues an ML-DSA CRL.
- [ ] The web app offers the two algorithms when creating a Private CA, with a note that clients must support ML-DSA (such as OpenSSL 3.5, Chrome 150).
