# 06: An Organization's own ML-DSA root

**What to build:** An Organization Administrator puts an ML-DSA Issuing CA under the Organization's own ML-DSA root, as they can today with RSA or ECDSA, and a root of any other algorithm is refused for it, so the chain is never part post-quantum.

**Blocked by:** 03

**Status:** done

- [x] An Organization root with an ML-DSA-65 or ML-DSA-87 key is accepted for an Issuing CA of the same algorithm; the Issuing CA's certificate that the root signs is checked as for any other.
- [x] A root of another algorithm, or an ML-DSA root for a non-ML-DSA Issuing CA, is refused with a 422 that says why.
- [x] A Managed Certificate issued from it verifies to the Organization's root.
- [x] Seam A tests cover each, following the existing organization-root tests.

## Comments

- An Organization-root Private CA now takes ML-DSA-65 and ML-DSA-87 like a platform-made one (ML-DSA-44 still refused); `/api/key-algorithms` lists them for both kinds, so the web offers them with no change. `caKeyAlgorithmsUnder` is gone: the set no longer depends on the kind.
- The rule is checked where the root arrives, in `signedCertificateRefusal` (`server/src/pki/ca-certificates.ts`): an ML-DSA Issuing CA needs the uploaded root, and every certificate between it and the root, to have a key of its own algorithm (so ML-DSA-87 under an ML-DSA-65 root is refused too); an Issuing CA that is not ML-DSA is refused under any ML-DSA certificate. Both are 422s that name the certificate and its key. A refused upload leaves the Issuing CA awaiting signature and the Private CA with no root, free to take the right one.
- Tests are in `server/test/private-ca-organization-root.test.ts` (the own-CA helpers there now take an algorithm); the two ML-DSA tests that pinned "refused for now" in `private-ca-ml-dsa.test.ts` now pin the new behaviour.
