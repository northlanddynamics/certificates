# 03: Tracer: an ML-DSA Private CA issues an ML-DSA Managed Certificate

**What to build:** End to end, an Organization Administrator creates a Private CA with a platform-made root whose key algorithm is ML-DSA-65 or ML-DSA-87. An Owner then creates a Managed Certificate on it from a pasted ML-DSA CSR (Key Custody: Owner), and the Certificate issued has a chain that verifies to the root. This works in the API and the web app. See `spec.md`, "Where each is allowed" and "What the API says".

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Creating a Private CA accepts `ml-dsa-65` and `ml-dsa-87`; its root and Issuing CA are signed with ML-DSA under the RFC 9881 OIDs, parameters absent.
- [ ] The CSR parser recognises ML-DSA-44, -65 and -87 CSRs, and its error messages list every supported algorithm.
- [ ] A Managed Certificate created or proposed on an ML-DSA Private CA with an ML-DSA CSR is issued; Approval works as for any other.
- [ ] The list of CAs a Managed Certificate can be issued from says which key algorithms each takes. The new Private CA and new Managed Certificate dialogs offer only those, and the Private CA dialog notes which clients can verify ML-DSA (OpenSSL 3.5 or later, Chrome 150 or later).
- [ ] Certificate facts name ML-DSA keys and signatures, and the Managed Certificate's details show them.
- [ ] Audit Events for creating the Private CA and the Managed Certificate record the ML-DSA key algorithm.
- [ ] A Seam A test creates each ML-DSA Private CA, issues an ML-DSA Managed Certificate from a CSR made with Bun's native ML-DSA, and verifies its chain to the root with the X.509 library.
