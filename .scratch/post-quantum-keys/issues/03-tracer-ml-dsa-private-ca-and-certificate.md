# 03: Tracer: an ML-DSA Private CA issues an ML-DSA Managed Certificate

**What to build:** End to end, an Organization Administrator creates a Private CA with a platform-made root whose key algorithm is ML-DSA-65 or ML-DSA-87. An Owner then creates a Managed Certificate on it from a pasted ML-DSA CSR (Key Custody: Owner), and the Certificate issued has a chain that verifies to the root. This works in the API and the web app. See `spec.md`, "Where each is allowed" and "What the API says".

**Blocked by:** 02

**Status:** done

- [x] Creating a Private CA accepts `ml-dsa-65` and `ml-dsa-87`; its root and Issuing CA are signed with ML-DSA under the RFC 9881 OIDs, parameters absent.
- [x] The CSR parser recognises ML-DSA-44, -65 and -87 CSRs, and its error messages list every supported algorithm.
- [x] A Managed Certificate created or proposed on an ML-DSA Private CA with an ML-DSA CSR is issued; Approval works as for any other.
- [x] The list of CAs a Managed Certificate can be issued from says which key algorithms each takes. The new Private CA and new Managed Certificate dialogs offer only those, and the Private CA dialog notes which clients can verify ML-DSA (OpenSSL 3.5 or later, Chrome 150 or later).
- [x] Certificate facts name ML-DSA keys and signatures, and the Managed Certificate's details show them.
- [x] Audit Events for creating the Private CA and the Managed Certificate record the ML-DSA key algorithm.
- [x] A Seam A test creates each ML-DSA Private CA, issues an ML-DSA Managed Certificate from a CSR made with Bun's native ML-DSA, and verifies its chain to the root with the X.509 library.

## Comments

- The list of CAs says what each takes in two places. Each Private CA carries `certificateKeyAlgorithms`, and `GET /api/key-algorithms` lists every algorithm, what a Private CA's keys may be under each kind of root, and what an ACME CA takes. The web reads both and keeps no copy of the rule.
- Part of ticket 04 landed here. Creating or proposing a Managed Certificate, and repointing one, refuse a key algorithm the CA does not take (ACME, an RSA/ECDSA Private CA, an ML-DSA Private CA), and `ml-dsa-44` is refused for a CA key. Each refusal is a 422 with tests in `server/test/private-ca-ml-dsa.test.ts`. A Name Change CSR, a Renewal CSR and the inventory filter remain for 04.
- Until ticket 06, an ML-DSA Private CA under the Organization's own root is refused with a 422 (`caKeyAlgorithmsUnder` in `private-ca.ts`), because nothing yet checks that the uploaded root is ML-DSA too. Ticket 06 should lift that.
- Deployments still take only ECDSA and RSA (ticket 08). An ML-DSA Private CA is refused for one with the same 422.
- The CSR Generator cannot make ML-DSA keys yet (ticket 09). For an ML-DSA key the key step offers the OpenSSL 3.5 command (`-newkey ml-dsa-NN`) or a pasted CSR. A pasted ML-DSA CSR is read without WebCrypto, so it also works in a browser without native ML-DSA, such as Chromium today; the server verifies its signature.
