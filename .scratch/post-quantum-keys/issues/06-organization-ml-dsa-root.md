# 06: An Organization's own ML-DSA root

**What to build:** An Organization Administrator puts an ML-DSA Issuing CA under the Organization's own ML-DSA root, as they can today with RSA or ECDSA, and a root of any other algorithm is refused for it, so the chain is never part post-quantum.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] An Organization root with an ML-DSA-65 or ML-DSA-87 key is accepted for an Issuing CA of the same algorithm; the Issuing CA's certificate that the root signs is checked as for any other.
- [ ] A root of another algorithm, or an ML-DSA root for a non-ML-DSA Issuing CA, is refused with a 422 that says why.
- [ ] A Managed Certificate issued from it verifies to the Organization's root.
- [ ] Seam A tests cover each, following the existing organization-root tests.
