# 05: ML-DSA CRLs, Revocation and Issuing CA rollover

**What to build:** Revocation and Issuing CA rollover on an ML-DSA Private CA work as on any other: a Revocation reissues the Issuing CA's CRL signed with ML-DSA in the same change, the CRL is served as usual, and a new Issuing CA can be added under an ML-DSA root with the same algorithm.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Revoking an ML-DSA Certificate reissues an ML-DSA-signed CRL that lists it and verifies with the X.509 library; the root's CRL of its Issuing CAs is ML-DSA-signed too.
- [ ] Scheduled CRL reissue works for ML-DSA CRLs, including one over 4 KB.
- [ ] Adding an Issuing CA under an ML-DSA root gives it a new ML-DSA key of the root's algorithm, and Managed Certificates issued from it verify to the same root.
- [ ] Seam A tests cover each, following the existing CRL and rollover tests.
