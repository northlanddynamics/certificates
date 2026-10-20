# 08: Agent-generated ML-DSA keys

**What to build:** A Deployment's Agent makes the ML-DSA key and CSR for a Managed Certificate on an ML-DSA Private CA. It keeps the key in its key store, and it hands the Deployment Script that key when the Certificate arrives, so ML-DSA Certificates are renewed and deployed hands-off. See `spec.md`, "Agent" and "Private key files".

**Blocked by:** 03

**Status:** done

- [x] The Agent makes ML-DSA-44, -65 and -87 keys with Cloudflare's CIRCL. It builds the PKCS#10 with Go's ASN.1 encoder:
  - the first name as CN;
  - a SubjectPublicKeyInfo holding the raw public key under the RFC 9881 OID, parameters absent;
  - the extensionRequest attribute as a SET holding a SEQUENCE of Extensions, carrying the SAN.

  It signs with randomized pure ML-DSA, empty context.
- [x] The key is stored as unencrypted seed-form PKCS#8 PEM (RFC 9881), readable only by the service account.
- [x] Keys are named by the hash of the Certificate's raw SubjectPublicKeyInfo; existing RSA and ECDSA keys keep their names.
- [x] The Agent contract and the `deployment.generate_key` payload allow the three algorithms, and the exported contract is regenerated. An Agent that does not know an algorithm fails the Work Item with a reason.
- [x] The new Deployment dialog offers ML-DSA only for an ML-DSA Private CA and warns that whatever the Deployment Script installs into must support ML-DSA.
- [x] Seam B tests, for each ML-DSA algorithm:
  - the CSR is read by Go's parser with its names;
  - the stored key re-imports from its seed;
  - a Deployment Run hands the script the right key;
  - an existing RSA or ECDSA key is still found.
- [x] A CSR the real Agent made is kept as a server-side fixture that the CSR parser accepts.
