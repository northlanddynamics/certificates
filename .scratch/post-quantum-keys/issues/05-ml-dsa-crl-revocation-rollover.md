# 05: ML-DSA CRLs, Revocation and Issuing CA rollover

**What to build:** Revocation and Issuing CA rollover on an ML-DSA Private CA work as on any other: a Revocation reissues the Issuing CA's CRL signed with ML-DSA in the same change, the CRL is served as usual, and a new Issuing CA can be added under an ML-DSA root with the same algorithm.

**Blocked by:** 03

**Status:** done

- [x] Revoking an ML-DSA Certificate reissues an ML-DSA-signed CRL that lists it and verifies with the X.509 library; the root's CRL of its Issuing CAs is ML-DSA-signed too.
- [x] Scheduled CRL reissue works for ML-DSA CRLs, including one over 4 KB.
- [x] Adding an Issuing CA under an ML-DSA root gives it a new ML-DSA key of the root's algorithm, and Managed Certificates issued from it verify to the same root.
- [x] Seam A tests cover each, following the existing CRL and rollover tests.

## Comments

- Nothing in the server needed to change: ticket 03 already made the CRL signer, the Issuing CA rollover and the Issuing CA revocation read the Private CA's key algorithm, and `makeCrl` signs through the same KMS path as certificates (the external μ for ML-DSA, ADR 0009), so a CRL of any size is signed. This ticket is the tests that pin it, in `server/test/private-ca-ml-dsa.test.ts`.
- The CRL over 4 KB is made by revoking 100 Certificates through the API (about 5 KB of TBSCertList, before the 3.3 KB ML-DSA-65 signature) and then running the scheduled pass.
- Also covered: Issuing CA revocation putting the Issuing CA on its root's ML-DSA CRL, a KMS that cannot sign refusing both revocations with 502, and a full rollover (repoint, retire, Renewal from the new Issuing CA, the retired one still publishing).
