// The warning under a pasted CSR reads the signature algorithm and nothing else; these tests run it here, under Bun's WebCrypto.
import { describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { readFileSync } from "node:fs";
import { generateCsr } from "../../web/src/lib/csr-generator";
import { weakSignatureWarning } from "../../web/src/lib/csr-signature";

const SIGNATURE = new URL("../../web/src/lib/csr-signature.ts", import.meta.url);

const RSA = { modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) };

async function csrWith(signingAlgorithm: object, keyAlgorithm: RsaHashedKeyGenParams) {
  const keys = (await crypto.subtle.generateKey(keyAlgorithm, true, ["sign", "verify"])) as CryptoKeyPair;
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name: "CN=a.example.com", keys, signingAlgorithm: signingAlgorithm as never });
  return csr;
}

// md5WithRSAEncryption (1.2.840.113549.1.1.4) is the same length as sha1WithRSAEncryption (…1.5), so the OID can be swapped in place.
async function md5Csr() {
  const sha1 = await csrWith({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1", ...RSA });
  const der = new Uint8Array(sha1.rawData);
  const oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
  const at = der.findIndex((_, i) => oid.every((b, j) => der[i + j] === b));
  expect(at).toBeGreaterThan(0);
  der[at + oid.length - 1] = 0x04;
  return x509.PemConverter.encode(der, "CERTIFICATE REQUEST");
}

describe("weakSignatureWarning", () => {
  test("says nothing about a CSR signed with SHA-256, SHA-384 or SHA-512, with RSA or ECDSA", async () => {
    for (const keyAlgorithm of ["ecdsa-p256", "ecdsa-p384", "rsa-2048"] as const)
      for (const hash of ["SHA-256", "SHA-384", "SHA-512"] as const) {
        const { csrPem } = await generateCsr({ keyAlgorithm, names: ["example.com"], hash });
        expect(weakSignatureWarning(csrPem)).toBeNull();
      }
  });

  test("warns about SHA-1", async () => {
    const csr = await csrWith({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1", ...RSA });
    expect(weakSignatureWarning(csr.toString("pem"))).toMatch(/SHA-1.*(refuse|likely)/);
  });

  test("warns about ECDSA with SHA-1 too", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name: "CN=a.example.com", keys, signingAlgorithm: { name: "ECDSA", hash: "SHA-1" } });
    expect(weakSignatureWarning(csr.toString("pem"))).toContain("SHA-1");
  });

  test("warns about MD5", async () => {
    expect(weakSignatureWarning(await md5Csr())).toMatch(/MD5.*(refuse|likely)/);
  });

  test("warns about RSA-PSS", async () => {
    const csr = await csrWith({ name: "RSA-PSS", hash: "SHA-256", saltLength: 32 }, { name: "RSA-PSS", hash: "SHA-256", ...RSA });
    expect(weakSignatureWarning(csr.toString("pem"))).toMatch(/RSA-PSS.*(refuse|likely)/);
  });

  test("says nothing about what is not a CSR, or is not yet one", async () => {
    expect(weakSignatureWarning("")).toBeNull();
    expect(weakSignatureWarning("not a csr")).toBeNull();
    expect(weakSignatureWarning("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----")).toBeNull();
    const { csrPem } = await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["example.com"] });
    expect(weakSignatureWarning(csrPem.slice(0, 120))).toBeNull();
  });

  test("shows nothing of the CSR but the algorithm, and imports only the X.509 library, so nothing is sent anywhere", async () => {
    const csr = await csrWith({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1", ...RSA });
    expect(weakSignatureWarning(csr.toString("pem"))).not.toMatch(/example\.com/);
    const code = readFileSync(SIGNATURE, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    const imported = [...code.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)].map((m) => m[1]!);
    for (const specifier of imported) expect(specifier).toBe("@peculiar/x509");
    expect(code).not.toMatch(/\bfetch\b|XMLHttpRequest|sendBeacon|WebSocket|EventSource/);
  });
});
