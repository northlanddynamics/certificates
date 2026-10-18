// The algorithms of the keys the platform deals with: Managed Certificates', Private CAs' and Agents'. Apart from
// csr.ts so that what needs only the list (the KMS) does not load the X.509 library.
/** ECDSA and RSA: until a Private CA signs with ML-DSA, the only key algorithms the API takes for a new key. */
export const CLASSICAL_KEY_ALGORITHMS = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"] as const;
export type ClassicalKeyAlgorithm = (typeof CLASSICAL_KEY_ALGORITHMS)[number];
/** Pure ML-DSA (FIPS 204), as RFC 9881 names it in X.509. */
export const ML_DSA_KEY_ALGORITHMS = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"] as const;
export type MlDsaKeyAlgorithm = (typeof ML_DSA_KEY_ALGORITHMS)[number];
export const KEY_ALGORITHMS = [...CLASSICAL_KEY_ALGORITHMS, ...ML_DSA_KEY_ALGORITHMS] as const;
export type KeyAlgorithm = (typeof KEY_ALGORITHMS)[number];
export const isMlDsa = (algorithm: KeyAlgorithm): algorithm is MlDsaKeyAlgorithm => (ML_DSA_KEY_ALGORITHMS as readonly string[]).includes(algorithm);
/** What a CA key can be, and so what the KMS makes signing keys of: every key algorithm but ML-DSA-44, too weak for a CA key. */
export const SIGNING_KEY_ALGORITHMS = KEY_ALGORITHMS.filter((algorithm): algorithm is SigningKeyAlgorithm => algorithm !== "ml-dsa-44");
export type SigningKeyAlgorithm = Exclude<KeyAlgorithm, "ml-dsa-44">;
export type MlDsaSigningKeyAlgorithm = Extract<SigningKeyAlgorithm, MlDsaKeyAlgorithm>;
