# Spec: Post-quantum keys (ML-DSA)

Status: ready-for-agent

## Problem Statement

Every key the platform deals with is RSA or ECDSA, which a large enough quantum computer breaks. Organizations running internal TLS on a Private CA want certificates whose whole chain is quantum-resistant, so that a recorded handshake or a forged signature is not a later risk, and some need CNSA 2.0 algorithms. Public CAs cannot help yet: the CA/Browser Forum has not allowed ML-DSA in publicly trusted TLS certificates, and Let's Encrypt has chosen Merkle Tree Certificates (staging late 2026, production 2027) rather than ML-DSA X.509.

## Solution

Support ML-DSA (FIPS 204, RFC 9881) as a key algorithm on Private CAs and on the Managed Certificates issued from them, with the key held by the Owner (via a pasted CSR or the CSR Generator) or by an Agent. ACME CAs, Device Certificates, ACME Account keys and the SCEP RA key stay RSA/ECDSA.

## User Stories

1. As an Organization Administrator, I want to create a Private CA whose root and Issuing CAs have ML-DSA keys, so that the Certificates it issues have a quantum-resistant chain.
2. As an Owner, I want a Managed Certificate on that Private CA to have an ML-DSA key, so that its own key is quantum-resistant too.
3. As an Owner who keeps my own key, I want the CSR Generator to make an ML-DSA key and CSR in my browser, so that I do not need OpenSSL 3.5.
4. As an Owner without a browser that can, or who prefers my own tooling, I want to be shown the OpenSSL command that makes the same CSR.
5. As an Organization Administrator, I want a Deployment's Agent to generate an ML-DSA key, so that ML-DSA certificates are renewed and deployed hands-off.
6. As anyone choosing a key algorithm, I want ML-DSA refused where it cannot be issued (an ACME CA), with a reason, so that I do not wait for an Issuance that will fail.

## Implementation Decisions

**Algorithms.** `ml-dsa-44`, `ml-dsa-65` and `ml-dsa-87`, pure ML-DSA with an empty context, identified by the RFC 9881 OIDs (`2.16.840.1.101.3.4.3.17`, `.18`, `.19`) with parameters absent. Not HashML-DSA, SLH-DSA, FN-DSA, composite or hybrid signatures, or ML-KEM keys.

**Where each is allowed.**
- A Private CA's key (root and Issuing CAs share one algorithm, as today): `ml-dsa-65` or `ml-dsa-87`. `ml-dsa-44` is not offered for CA keys.
- A Managed Certificate's key: all three, only when it is issued from a Private CA whose key algorithm is ML-DSA. A Managed Certificate on an ACME CA, or on an RSA/ECDSA Private CA, refuses them with a 422 saying why. An ML-DSA leaf under an ECDSA CA gains no quantum resistance and an ML-DSA CA signing an ECDSA leaf leaves the leaf weak, so ML-DSA is all or nothing in a chain.
- Device Certificates, ACME Account keys and the SCEP RA key: unchanged.

**X.509 library.** `@peculiar/x509` moves from 1.14.3 to 2.x in the server and the web app: 1.14.3 cannot verify an ML-DSA CSR, 2.2.0 can. 2.x needs `reflect-metadata` imported before it loads, and the `@peculiar/asn1-schema` override in the root `package.json` must be rechecked. Bun 1.4.2 generates, signs and verifies ML-DSA in both `node:crypto` and WebCrypto, and `createPublicKey` reports `ml-dsa-44/65/87`.

**KMS signing (amends ADR 0007).** The `Kms` seam signs a digest with one hash per algorithm; pure ML-DSA signs the message. The seam gains signing of the ML-DSA *external μ* (the 64-byte message representative, SHAKE256 of the public key hash and the message, computed by the platform), which keeps a large CRL off the KMS's message size limit. AWS KMS takes μ as `MessageType: EXTERNAL_MU` (verify before the AWS implementation is written); Google Cloud KMS's support is to be checked; Azure Key Vault has no ML-DSA keys, so an Organization on it cannot have an ML-DSA Private CA. The local KMS implements it with Bun's native ML-DSA. The algorithm-to-hash table in `kms.ts` does not apply to ML-DSA, and signatures are returned raw (there is no DER form to convert).

**Private keys at rest.** Wherever a key file is produced (CSR Generator download, Agent keystore), it is PKCS#8 in the RFC 9881 seed form: the 32-byte seed as `[0] IMPLICIT OCTET STRING`. Bun imports it; OpenSSL 3.5 reads it.

**Agent.** Go's `crypto/x509` cannot make an ML-DSA CSR, marshal an ML-DSA key or return an ML-DSA certificate's public key. The Agent uses `github.com/cloudflare/circl/sign/mldsa` (v1.6.5 needs Go 1.25, which `go.mod` already names) and builds the PKCS#10 with `encoding/asn1`: subject, SubjectPublicKeyInfo with the raw public key, and the extensionRequest attribute as a SET holding a SEQUENCE of Extensions. Signing is pure ML-DSA with an empty context, randomized. `KeyFile` names keys by the hash of `leaf.RawSubjectPublicKeyInfo` rather than `MarshalPKIXPublicKey(leaf.PublicKey)`, which is nil for ML-DSA; this gives the same file name for existing keys because the CA copies the CSR's SubjectPublicKeyInfo unchanged. When the Agent moves to Go 1.26, the standard library's `crypto/mldsa` may replace circl; the hand-built CSR stays. A prototype of this CSR was verified by `@peculiar/x509` 2.2.0 and parsed by Go's `x509.ParseCertificateRequest` with its SAN.

**CSR Generator.** Uses the browser's WebCrypto ML-DSA when it has it (feature-detected by trying `generateKey`), otherwise `@noble/post-quantum` (pure JS), loaded only when an ML-DSA algorithm is chosen. Without WebCrypto support the CSR is built from `@peculiar/asn1-csr` and `@peculiar/asn1-x509` in the same shape as the Agent's. The key never leaves the browser (ADR 0002 holds). ML-DSA has no hash choice, so the "Advanced" signature section hides for it. The page also shows the equivalent `openssl req -new -newkey ml-dsa-65 ...` command. Check whether `@noble/post-quantum` has been independently audited before shipping.

**Deployment Scripts.** Whatever consumes an ML-DSA key and Certificate (a web server, a load balancer) must support ML-DSA, such as OpenSSL 3.5 or later; the platform cannot help with that, and says so in the UI where an ML-DSA algorithm is chosen for a Deployment.

**Docs.** A new ADR amending ADR 0007 for ML-DSA KMS signing; `CONTEXT.md`'s CSR Generator entry no longer says the key is always made with WebCrypto.

## Testing Decisions

- The KMS contract test (`server/test/support/kms-signing-contract.ts`) runs for the ML-DSA algorithms: create, public key, sign μ, verify the full-message signature with WebCrypto.
- A Private CA test issues an ML-DSA Certificate and CRL and verifies both with `@peculiar/x509`.
- The existing server test that runs the CSR Generator through `parseCsr` covers the ML-DSA algorithms (noble path, since the test runtime's WebCrypto has native ML-DSA, also the native path).
- Agent: a keystore test generates each ML-DSA key, checks the CSR parses with `x509.ParseCertificateRequest` with its names, the PEM key re-imports from its seed, and `KeyFile` finds the key from an issued ML-DSA Certificate. A server-side fixture of an Agent-made CSR goes through `parseCsr`.
- Refusals: ML-DSA on an ACME CA, and on an RSA/ECDSA Private CA, each a 422.

## Out of Scope

- ML-DSA for publicly trusted certificates, and Merkle Tree Certificates (revisit when Let's Encrypt's ACME extension is published).
- ML-DSA Device Certificates and SCEP.
- Composite or hybrid (ML-DSA + ECDSA) certificates, SLH-DSA, FN-DSA.
- An AWS or Azure KMS implementation (only the local one exists today).
- Mixing algorithms in one chain.
