# 04: ML-DSA through a Managed Certificate's life, and refusals where it cannot work

**What to build:** Name Change and Renewal work with ML-DSA CSRs, and ML-DSA is refused, before anything waits on it, wherever a key algorithm meets a CA that cannot take it. See `spec.md`, "Where each is allowed".

**Blocked by:** 03

**Status:** done

- [x] A Name Change and a Renewal on an ML-DSA Managed Certificate accept an ML-DSA CSR of the same algorithm and refuse one of another, as for any key algorithm.
- [x] These are refused with a 422 that says why: an ML-DSA key algorithm on an ACME CA or on an RSA/ECDSA Private CA; an RSA/ECDSA key algorithm on an ML-DSA Private CA; `ml-dsa-44` for a Private CA's key. This holds when a Managed Certificate is created or proposed, and for a Name Change or Renewal CSR.
- [x] The inventory filters by the three ML-DSA key algorithms.
- [x] Seam A tests cover each refusal and the Name Change and Renewal.

## Comments

- Most of the refusals landed with ticket 03 (creating, proposing and repointing a Managed Certificate; `ml-dsa-44` for a CA key). This ticket adds the Name Change and Renewal paths: their CSR must be of the Managed Certificate's key algorithm, which its CA already takes, so a CSR of another kind is refused with a 422 that now says why (`mixedChainReason` in `key-algorithms.ts`, shared with the CA refusal) when one is ML-DSA and the other is not. A CSR of another ML-DSA algorithm gets the plain "key algorithm differs" 422, as for any algorithm.
- The inventory's `keyAlgorithm` filter and the web's Key algorithm facet were already built from the full algorithm list; the tests now cover each ML-DSA algorithm.
- The tests need Bun 1.4.2 or later (native ML-DSA); on 1.3.x every ML-DSA test fails with "unsupported key type".
