// The CSR Viewer lives in the web package and runs in the user's browser; these tests run its reader here, under Bun's
// WebCrypto, and hold its verdict to the server's parseCsr, so the viewer never says "the platform takes it" of a CSR the
// server refuses.
import { describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { readFileSync } from "node:fs";
import { CsrError, MAX_CSR_LENGTH as SERVER_MAX_CSR_LENGTH, parseCsr } from "../src/pki/csr";
import { generateCsr } from "../../web/src/lib/csr-generator";
import { parseCsrDetails, type CsrDetails } from "../../web/src/lib/csr-details";
import { MAX_CSR_LENGTH, readCsrText, textOfCsrFile } from "../../web/src/lib/csr-input";
import { verifyMlDsaCsr } from "../../web/src/lib/csr-ml-dsa";

const fixture = (name: string) => readFileSync(new URL(`./fixtures/agent/${name}.csr.pem`, import.meta.url), "utf8");
const DETAILS = [new URL("../../web/src/lib/csr-details.ts", import.meta.url), new URL("../../web/src/lib/csr-input.ts", import.meta.url)];

async function detailsOf(pem: string): Promise<CsrDetails> {
  const reading = await parseCsrDetails(pem);
  if (!reading.ok) throw new Error(reading.error);
  return reading.details;
}

describe("parseCsrDetails", () => {
  test("reads the subject, names, key, signature, extensions and fingerprint of a generated CSR", async () => {
    const { csrPem } = await generateCsr({
      keyAlgorithm: "ecdsa-p256",
      names: ["example.com", "*.example.com"],
      commonName: "example.com",
      subject: { organization: "Example Inc", country: "US" },
    });
    const details = await detailsOf(csrPem);
    expect(details.subject.map((f) => `${f.type}=${f.value}`).sort()).toEqual(["C=US", "CN=example.com", "O=Example Inc"]);
    expect(details.subject.find((f) => f.type === "O")?.label).toBe("Organization");
    expect(details.names.filter((n) => n.source === "san").map((n) => n.value)).toEqual(["example.com", "*.example.com"]);
    expect(details.names.find((n) => n.value === "*.example.com")?.wildcard).toBe(true);
    // The CN repeats a SAN.
    expect(details.names.find((n) => n.source === "cn")?.repeat).toBe(true);
    expect(details.distinctNames).toEqual(["example.com", "*.example.com"]);
    expect(details.key).toMatchObject({ algorithm: "ecdsa-p256", label: "ECDSA P-256" });
    expect(details.key.publicKeyPem).toStartWith("-----BEGIN PUBLIC KEY-----");
    expect(details.signature).toEqual({ algorithm: "ECDSA with SHA-256", check: "valid" });
    expect(details.extensions.map((e) => e.label)).toEqual(["Subject alternative names"]);
    expect(details.extensions[0]!.summary).toBe("2 names, listed above");
    expect(details.attributes).toEqual([]);
    expect(details.acceptable).toBe(true);
    expect(details.fit.map((c) => c.ok)).toEqual([true, true, true]);
    expect(details.pem).toBe(csrPem.trim().replace(/\r/g, ""));
  });

  test("names the CSR as the server names it, and the key as a SubjectPublicKeyInfo", async () => {
    const { csrPem } = await generateCsr({ keyAlgorithm: "rsa-2048", names: ["a.example.com"], commonName: "a.example.com" });
    const details = await detailsOf(csrPem);
    const parsed = await parseCsr(csrPem);
    expect(details.fingerprint).toBe(parsed.fingerprint);
    expect(details.key.sha256).toBe(new Bun.CryptoHasher("sha256").update(parsed.publicKey).digest("hex"));
    expect(details.key.label).toBe("RSA 2048");
  });

  test("says a signature that does not verify is invalid, and the platform would refuse it", async () => {
    const { csrPem } = await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["a.example.com"] });
    const body = csrPem.split("\n").filter((line) => !line.startsWith("-----")).join("");
    const bytes = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
    bytes[bytes.length - 3] = ~bytes[bytes.length - 3]! & 0xff;
    const damaged = x509.PemConverter.encode(bytes.buffer, "CERTIFICATE REQUEST");
    const details = await detailsOf(damaged);
    expect(details.signature.check).toBe("invalid");
    expect(details.acceptable).toBe(false);
    await expect(parseCsr(damaged)).rejects.toThrow(CsrError);
  });

  test("warns of a CSR with no subject alternative name, and still reads its CN as a name", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name: "CN=cn-only.example.com", keys, signingAlgorithm: { name: "ECDSA", hash: "SHA-256" } });
    const details = await detailsOf(csr.toString("pem"));
    expect(details.distinctNames).toEqual(["cn-only.example.com"]);
    expect(details.warnings.join(" ")).toContain("no subject alternative names");
    expect((await parseCsr(csr.toString("pem"))).names).toEqual(["cn-only.example.com"]);
  });

  test("flags a name the server refuses, and agrees it refuses the CSR", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=a.example.com",
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "a.example.com" }, { type: "ip", value: "10.0.0.1" }, { type: "email", value: "a@example.com" }])],
    });
    const details = await detailsOf(csr.toString("pem"));
    expect(details.names.filter((n) => n.problem).map((n) => n.type)).toEqual(["IP", "Email"]);
    expect(details.distinctNames).toEqual(["a.example.com"]);
    expect(details.acceptable).toBe(false);
    expect(details.fit.find((c) => c.id === "names")!.ok).toBe(false);
    await expect(parseCsr(csr.toString("pem"))).rejects.toThrow(CsrError);
  });

  test("names a key the platform does not take, and agrees it refuses the CSR", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-521" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=a.example.com",
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-512" },
      extensions: [new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "a.example.com" }])],
    });
    const details = await detailsOf(csr.toString("pem"));
    expect(details.key).toMatchObject({ algorithm: null, label: "ECDSA P-521" });
    expect(details.acceptable).toBe(false);
    await expect(parseCsr(csr.toString("pem"))).rejects.toThrow(CsrError);
  });

  test("shows requested key usage, extended key usage and basic constraints in words, and warns of CA:TRUE", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=a.example.com",
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "a.example.com" }]),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment, true),
        new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth]),
        new x509.BasicConstraintsExtension(true, 0, true),
      ],
    });
    const details = await detailsOf(csr.toString("pem"));
    const byLabel = Object.fromEntries(details.extensions.map((e) => [e.label, e]));
    expect(byLabel["Key usage"]).toMatchObject({ critical: true, summary: "Digital signature, Key encipherment" });
    expect(byLabel["Extended key usage"]!.summary).toBe("TLS server authentication, TLS client authentication");
    expect(byLabel["Basic constraints"]).toMatchObject({ critical: true, summary: "CA, path length 0" });
    expect(details.warnings.join(" ")).toContain("CA:TRUE");
  });

  test("never shows the value of a challenge password", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=a.example.com",
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      attributes: [new x509.ChallengePasswordAttribute("s3cret-challenge")],
      extensions: [new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "a.example.com" }])],
    });
    const details = await detailsOf(csr.toString("pem"));
    expect(details.attributes).toEqual([{ oid: "1.2.840.113549.1.9.7", label: "Challenge password", summary: "Present; its value is not shown" }]);
    expect(JSON.stringify(details.attributes)).not.toContain("s3cret");
  });

  test("warns of a SHA-1 signature, as the warning under a pasted CSR does", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=a.example.com",
      keys,
      signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
      extensions: [new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "a.example.com" }])],
    });
    const details = await detailsOf(csr.toString("pem"));
    expect(details.signature.algorithm).toBe("RSA PKCS#1 v1.5 with SHA-1");
    expect(details.warnings.join(" ")).toContain("SHA-1");
  });

  for (const algorithm of ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"] as const) {
    test(`reads an ${algorithm} CSR, whose signature the browser can check itself, as the server does`, async () => {
      const pem = fixture(algorithm);
      const details = await detailsOf(pem);
      expect(details.key.algorithm).toBe(algorithm);
      expect(details.signature.check).toBe("valid");
      expect(details.acceptable).toBe(true);
      expect((await parseCsr(pem)).keyAlgorithm).toBe(algorithm);
      // The path a browser with no ML-DSA in WebCrypto takes.
      expect(verifyMlDsaCsr(new x509.Pkcs10CertificateRequest(pem).rawData)).toBe(true);
    });
  }

  test("does not verify an ML-DSA CSR whose signature was changed", () => {
    const der = new x509.Pkcs10CertificateRequest(fixture("ml-dsa-44")).rawData.slice(0);
    const view = new Uint8Array(der);
    view[der.byteLength - 10] = ~view[der.byteLength - 10]! & 0xff;
    expect(verifyMlDsaCsr(der)).toBe(false);
  });

  test("says why text that is not a CSR cannot be read", async () => {
    const reading = await parseCsrDetails("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----");
    expect(reading.ok).toBe(false);
  });
});

describe("readCsrText", () => {
  test("takes the PEM of a CSR, however the whitespace was damaged, as one clean block", async () => {
    const { csrPem } = await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["a.example.com"] });
    const squashed = csrPem.replace(/\n/g, " ");
    const read = readCsrText(`\n\n  ${squashed}  \n`);
    expect(read).toEqual({ kind: "csr", pem: csrPem.trim(), ignored: 0 });
  });

  test("takes the base64 of a CSR that lost its header and footer", async () => {
    const { csrPem } = await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["a.example.com"] });
    const bare = csrPem.split("\n").filter((line) => !line.startsWith("-----")).join("");
    expect(readCsrText(bare)).toEqual({ kind: "csr", pem: csrPem.trim(), ignored: 0 });
  });

  test("takes the older NEW CERTIFICATE REQUEST label", async () => {
    const { csrPem } = await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["a.example.com"] });
    const read = readCsrText(csrPem.replaceAll("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"));
    expect(read).toEqual({ kind: "csr", pem: csrPem.trim(), ignored: 0 });
  });

  test("reads the first of several CSRs and counts the rest", async () => {
    const a = (await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["a.example.com"] })).csrPem;
    const b = (await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["b.example.com"] })).csrPem;
    expect(readCsrText(`${a}\n${b}`)).toEqual({ kind: "csr", pem: a.trim(), ignored: 1 });
  });

  test("refuses a private key and says to clear it, even beside a CSR", async () => {
    const { csrPem, keyPem } = await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["a.example.com"] });
    for (const text of [keyPem, `${csrPem}\n${keyPem}`, keyPem.replace("PRIVATE KEY", "RSA PRIVATE KEY")]) {
      expect(readCsrText(text)).toMatchObject({ kind: "refused", clear: true });
    }
  });

  test("tells a certificate from a CSR", () => {
    const read = readCsrText("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----");
    expect(read).toMatchObject({ kind: "refused", clear: false });
    expect(read && read.kind === "refused" && read.problem).toContain("certificate, not a CSR");
  });

  test("says nothing of nothing, and refuses prose and text far larger than a CSR", () => {
    expect(readCsrText("  \n ")).toBeNull();
    expect(readCsrText("hello there")).toMatchObject({ kind: "refused" });
    expect(readCsrText("A".repeat(MAX_CSR_LENGTH + 1))).toMatchObject({ kind: "refused" });
  });

  test("holds the same size limit as the server", () => {
    expect(MAX_CSR_LENGTH).toBe(SERVER_MAX_CSR_LENGTH);
  });
});

describe("textOfCsrFile", () => {
  test("makes PEM of a DER CSR, which then reads as a CSR the server takes", async () => {
    const { csrPem } = await generateCsr({ keyAlgorithm: "ecdsa-p384", names: ["a.example.com"] });
    const der = new Uint8Array(new x509.Pkcs10CertificateRequest(csrPem).rawData);
    const read = readCsrText(textOfCsrFile(der));
    expect(read).toEqual({ kind: "csr", pem: csrPem.trim(), ignored: 0 });
    expect((await parseCsr(read?.kind === "csr" ? read.pem : "")).keyAlgorithm).toBe("ecdsa-p384");
  });

  test("leaves a text file as it is", () => {
    expect(textOfCsrFile(new TextEncoder().encode("-----BEGIN CERTIFICATE REQUEST-----"))).toBe("-----BEGIN CERTIFICATE REQUEST-----");
  });
});

describe("the viewer's imports", () => {
  test("are the X.509 library and the CSR modules alone, and nothing sends anything, so a CSR read here goes nowhere", () => {
    const allowed = ["@peculiar/x509", "./csr-generator", "./csr-inspect", "./csr-names", "./csr-signature", "./csr-ml-dsa"];
    for (const file of DETAILS) {
      const code = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      const imported = [...code.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)].map((m) => m[1]!);
      for (const specifier of imported) expect(allowed).toContain(specifier);
      expect(code).not.toMatch(/\bfetch\b|XMLHttpRequest|sendBeacon|WebSocket|EventSource/);
    }
  });
});
