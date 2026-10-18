# 04: ML-DSA through a Managed Certificate's life, and refusals where it cannot work

**What to build:** Name Change and Renewal work with ML-DSA CSRs, and ML-DSA is refused, before anything waits on it, wherever a key algorithm meets a CA that cannot take it. See `spec.md`, "Where each is allowed".

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] A Name Change and a Renewal on an ML-DSA Managed Certificate accept an ML-DSA CSR of the same algorithm and refuse one of another, as for any key algorithm.
- [ ] These are refused with a 422 that says why: an ML-DSA key algorithm on an ACME CA or on an RSA/ECDSA Private CA; an RSA/ECDSA key algorithm on an ML-DSA Private CA; `ml-dsa-44` for a Private CA's key. This holds when a Managed Certificate is created or proposed, and for a Name Change or Renewal CSR.
- [ ] The inventory filters by the three ML-DSA key algorithms.
- [ ] Seam A tests cover each refusal and the Name Change and Renewal.
