# 05: Agent-generated ML-DSA keys

**What to build:** An Agent carries out `deployment.generate_key` for the ML-DSA algorithms, and finds the key again from the issued Certificate. See `spec.md`, "Agent" and "Private keys at rest".

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] `keystore.generate` makes ML-DSA keys with `github.com/cloudflare/circl/sign/mldsa`; the CSR is built with `encoding/asn1` (extensionRequest as a SET holding a SEQUENCE of Extensions) and signed with pure ML-DSA, empty context.
- [ ] The key is stored as seed-form PKCS#8 PEM (RFC 9881).
- [ ] `KeyFile` and the file name hash `RawSubjectPublicKeyInfo`; a test shows existing RSA/ECDSA keys keep their file names.
- [ ] The agent contract (`agent/contract/`) and the platform's `deployment.generate_key` payload schema allow the new algorithms; `contract:export` regenerated.
- [ ] Tests per spec: Go's `x509.ParseCertificateRequest` reads the CSR and its names; the key re-imports from its seed; a server fixture of an Agent CSR passes `parseCsr`.
- [ ] The new Deployment dialog notes that the Deployment Script's target must support ML-DSA.
