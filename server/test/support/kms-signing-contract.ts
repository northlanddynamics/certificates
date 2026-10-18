// The contract every Kms's signing keys keep: a key made for one context (an Organization's id) gives its public key
// and signs what WebCrypto verifies (a digest for ECDSA and RSA, the external μ of the message for ML-DSA), and is
// refused under any other context. The local KMS runs it in kms.test.ts; an AWS KMS, Google Cloud KMS or Azure Key Vault
// implementation runs it unchanged against its own service.
import { describe, expect, test } from "bun:test";
import { webcrypto } from "node:crypto";
import { isMlDsa, type ClassicalKeyAlgorithm } from "../../src/pki/csr";
import { SIGNATURE_HASH, SIGNING_KEY_ALGORITHMS, externalMu, type Kms, type SigningKeyAlgorithm } from "../../src/platform/crypto/kms";

const IMPORT_PARAMS: Record<SigningKeyAlgorithm, Algorithm> = {
  "ecdsa-p256": { name: "ECDSA", namedCurve: "P-256" } as EcKeyImportParams,
  "ecdsa-p384": { name: "ECDSA", namedCurve: "P-384" } as EcKeyImportParams,
  "rsa-2048": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as RsaHashedImportParams,
  "rsa-3072": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as RsaHashedImportParams,
  "rsa-4096": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as RsaHashedImportParams,
  // Pure ML-DSA with an empty context, over the whole message.
  "ml-dsa-65": { name: "ML-DSA-65" },
  "ml-dsa-87": { name: "ML-DSA-87" },
};

async function verifies(algorithm: SigningKeyAlgorithm, spki: Uint8Array, signature: Uint8Array, data: Uint8Array) {
  const params = IMPORT_PARAMS[algorithm];
  const key = await webcrypto.subtle.importKey("spki", new Uint8Array(spki), params, false, ["verify"]);
  const verifyParams = isMlDsa(algorithm) ? params : { name: params.name, hash: SIGNATURE_HASH[algorithm] };
  return webcrypto.subtle.verify(verifyParams, key, new Uint8Array(signature), new Uint8Array(data));
}

const digestOf = async (algorithm: ClassicalKeyAlgorithm, data: Uint8Array) =>
  new Uint8Array(await webcrypto.subtle.digest(SIGNATURE_HASH[algorithm], new Uint8Array(data)));

/** What the platform hands the KMS to sign `data` with a key of `algorithm` whose public key is `spki`. */
const toSign = async (algorithm: SigningKeyAlgorithm, spki: Uint8Array, data: Uint8Array) =>
  isMlDsa(algorithm) ? externalMu(algorithm, spki, data) : digestOf(algorithm, data);

export function kmsSigningContract(name: string, makeKms: () => Kms | Promise<Kms>) {
  describe(`${name}: signing keys`, () => {
    const ORG = "organization-a";
    const data = new TextEncoder().encode("the bytes of a certificate to be signed");

    test.each([...SIGNING_KEY_ALGORITHMS])("a %s key signs what verifies under its public key", async (algorithm) => {
      const kms = await makeKms();
      const key = await kms.createSigningKey(algorithm, ORG);
      const spki = await kms.publicKey(key, ORG);
      const signature = await kms.sign(key, ORG, await toSign(algorithm, spki, data));

      expect(await verifies(algorithm, spki, signature, data)).toBe(true);
      expect(await verifies(algorithm, spki, signature, new TextEncoder().encode("other bytes"))).toBe(false);
    });

    // A KMS limits the message it takes (AWS KMS to 4 KB), and a CRL can be far larger; through μ any size is signed.
    test.each(["ml-dsa-65", "ml-dsa-87"] as const)("a %s key signs a message over 4 KB as pure ML-DSA", async (algorithm) => {
      const kms = await makeKms();
      const key = await kms.createSigningKey(algorithm, ORG);
      const spki = await kms.publicKey(key, ORG);
      const large = webcrypto.getRandomValues(new Uint8Array(100_000));
      const signature = await kms.sign(key, ORG, await toSign(algorithm, spki, large));

      expect(await verifies(algorithm, spki, signature, large)).toBe(true);
    });

    test.each(["ecdsa-p256", "ml-dsa-65", "ml-dsa-87"] as const)("a %s key is refused under any context but the one it was made for", async (algorithm) => {
      const kms = await makeKms();
      const key = await kms.createSigningKey(algorithm, ORG);
      const input = await toSign(algorithm, await kms.publicKey(key, ORG), data);

      await expect(kms.sign(key, "organization-b", input)).rejects.toThrow();
      await expect(kms.publicKey(key, "organization-b")).rejects.toThrow();
      expect(await kms.sign(key, ORG, input)).toBeInstanceOf(Uint8Array);
    });

    test("each key is its own", async () => {
      const kms = await makeKms();
      const first = await kms.createSigningKey("ecdsa-p256", ORG);
      const second = await kms.createSigningKey("ecdsa-p256", ORG);
      const signature = await kms.sign(first, ORG, await digestOf("ecdsa-p256", data));

      expect(await verifies("ecdsa-p256", await kms.publicKey(second, ORG), signature, data)).toBe(false);
    });

    test("a digest not made with the key algorithm's hash is refused", async () => {
      const kms = await makeKms();
      const key = await kms.createSigningKey("ecdsa-p384", ORG);

      await expect(kms.sign(key, ORG, await digestOf("ecdsa-p256", data))).rejects.toThrow();
    });

    test("an ML-DSA key refuses anything but a 64-byte μ", async () => {
      const kms = await makeKms();
      const key = await kms.createSigningKey("ml-dsa-65", ORG);

      await expect(kms.sign(key, ORG, await digestOf("ecdsa-p256", data))).rejects.toThrow();
    });

    test("no ML-DSA-44 key is made, being too weak for a CA key", async () => {
      const kms = await makeKms();

      await expect(kms.createSigningKey("ml-dsa-44" as SigningKeyAlgorithm, ORG)).rejects.toThrow();
    });
  });
}
