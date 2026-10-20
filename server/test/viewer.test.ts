// The PEM Parser (the Viewer) lives in the web package and runs in the user's browser; these tests run its reader here, under Bun's
// WebCrypto, and hold its verdict to the server's parseCsr, so the viewer never says "the platform takes it" of a CSR the
// server refuses.
import { describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { readFileSync } from "node:fs";
import { CsrError, MAX_CSR_LENGTH as SERVER_MAX_CSR_LENGTH, parseCsr } from "../src/pki/csr";
import { generateCsr } from "../../web/src/lib/csr-generator";
import { parseCertificateDetails, type CertificateDetails } from "../../web/src/lib/certificate-details";
import { parseCsrDetails, type CsrDetails } from "../../web/src/lib/csr-details";
import { conversionsOf, fileBaseOf, type ConversionFormat } from "../../web/src/lib/pki-convert";
import { MAX_CSR_LENGTH, containsPrivateKey, isPkcs7Der, kindOfDer, readPkiText, textOfPkiFile, type PkiItem } from "../../web/src/lib/pki-input";
import { verifyMlDsaCertificate, verifyMlDsaCsr } from "../../web/src/lib/csr-ml-dsa";

const fixture = (name: string) => readFileSync(new URL(`./fixtures/agent/${name}.csr.pem`, import.meta.url), "utf8");
const DETAILS = [new URL("../../web/src/lib/csr-details.ts", import.meta.url), new URL("../../web/src/lib/pki-input.ts", import.meta.url), new URL("../../web/src/lib/pki-common.ts", import.meta.url), new URL("../../web/src/lib/certificate-details.ts", import.meta.url), new URL("../../web/src/lib/pki-convert.ts", import.meta.url)];

async function detailsOf(pem: string): Promise<CsrDetails> {
  const reading = await parseCsrDetails(pem);
  if (!reading.ok) throw new Error(reading.error);
  return reading.details;
}

const NOW = new Date("2026-06-15T12:00:00Z");
const daysFromNow = (days: number) => new Date(NOW.getTime() + days * 86_400_000);
const ECDSA = { name: "ECDSA", hash: "SHA-256" };

async function certificateOf(pem: string, now = NOW): Promise<CertificateDetails> {
  const reading = await parseCertificateDetails(pem, now);
  if (!reading.ok) throw new Error(reading.error);
  return reading.details;
}

/** A certificate that signed itself. */
async function selfSigned(name = "ca.example.com", options: { from?: Date; to?: Date; extensions?: x509.Extension[]; signingAlgorithm?: object; keys?: CryptoKeyPair } = {}) {
  const keys = options.keys ?? ((await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair);
  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "0a1b",
    name: `CN=${name}, O=Example Inc`,
    notBefore: options.from ?? daysFromNow(-10),
    notAfter: options.to ?? daysFromNow(80),
    keys,
    signingAlgorithm: (options.signingAlgorithm ?? ECDSA) as EcdsaParams,
    extensions: options.extensions ?? [new x509.BasicConstraintsExtension(true, undefined, true)],
  });
  return { certificate, keys };
}

/** A certificate that a CA signed, which this page does not have. */
async function issuedBy(extensions: x509.Extension[], options: { from?: Date; to?: Date } = {}) {
  const ca = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const leaf = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  return x509.X509CertificateGenerator.create({
    serialNumber: "0f",
    subject: "CN=www.example.com",
    issuer: "CN=Example Issuing CA, O=Example Inc",
    notBefore: options.from ?? daysFromNow(-10),
    notAfter: options.to ?? daysFromNow(80),
    signingKey: ca.privateKey,
    publicKey: leaf.publicKey,
    signingAlgorithm: ECDSA,
    extensions,
  });
}

const names = (...values: string[]) => new x509.SubjectAlternativeNameExtension(values.map((value) => ({ type: "dns" as const, value })));
const certificatePem = (certificate: x509.X509Certificate) => certificate.toString("pem");

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

describe("parseCertificateDetails", () => {
  test("reads a self-signed CA: who, when, key, signature, extensions and the digests that name it", async () => {
    const { certificate } = await selfSigned();
    const details = await certificateOf(certificatePem(certificate));
    expect(details.subject.map((f) => `${f.type}=${f.value}`).sort()).toEqual(["CN=ca.example.com", "O=Example Inc"]);
    expect(details.issuer).toEqual(details.subject);
    expect(details.serialNumber).toBe("0a1b");
    expect(details.selfIssued).toBe(true);
    expect(details.isCa).toBe(true);
    expect(details.validity).toMatchObject({ status: "valid", days: 80, lifetimeDays: 90 });
    expect(details.validity.notAfter).toBe(daysFromNow(80).toISOString().replace(/\.\d{3}Z$/, ".000Z"));
    expect(details.key).toMatchObject({ algorithm: "ecdsa-p256", label: "ECDSA P-256" });
    expect(details.signature).toEqual({ algorithm: "ECDSA with SHA-256", check: "valid" });
    expect(details.extensions.map((e) => `${e.label}: ${e.summary}`)).toEqual(["Basic constraints: CA"]);
    expect(details.fingerprint).toBe(new Bun.CryptoHasher("sha256").update(new Uint8Array(certificate.rawData)).digest("hex"));
    expect(details.sha1).toBe(new Bun.CryptoHasher("sha1").update(new Uint8Array(certificate.rawData)).digest("hex"));
    expect(details.pem).toBe(certificatePem(certificate).trim());
  });

  test("gives a certificate the same key digest as a CSR for the same key, so the two can be told together", async () => {
    const { certificate, keys } = await selfSigned("www.example.com", { extensions: [names("www.example.com")] });
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name: "CN=www.example.com", keys, signingAlgorithm: ECDSA, extensions: [names("www.example.com")] });
    expect((await certificateOf(certificatePem(certificate))).key.sha256).toBe((await detailsOf(csr.toString("pem"))).key.sha256);
  });

  test("reads the names, and the access, distribution and usage extensions of an issued certificate, and leaves its signature unchecked", async () => {
    const certificate = await issuedBy([
      names("www.example.com", "*.example.com"),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
      new x509.AuthorityInfoAccessExtension({ ocsp: "http://ocsp.example.com", caIssuers: "http://ca.example.com/ca.crt" }),
      new x509.CRLDistributionPointsExtension(["http://crl.example.com/ca.crl"]),
      new x509.CertificatePolicyExtension(["2.23.140.1.2.1"]),
    ]);
    const details = await certificateOf(certificatePem(certificate));
    expect(details.selfIssued).toBe(false);
    expect(details.isCa).toBe(false);
    expect(details.issuer.find((f) => f.type === "CN")?.value).toBe("Example Issuing CA");
    expect(details.names).toEqual([
      { type: "DNS", value: "www.example.com", wildcard: false },
      { type: "DNS", value: "*.example.com", wildcard: true },
    ]);
    expect(details.signature.check).toBe("unchecked");
    const byLabel = Object.fromEntries(details.extensions.map((e) => [e.label, e.summary]));
    expect(byLabel["Extended key usage"]).toBe("TLS server authentication");
    expect(byLabel["Authority information access"]).toBe("OCSP http://ocsp.example.com; CA issuers http://ca.example.com/ca.crt");
    expect(byLabel["CRL distribution points"]).toBe("http://crl.example.com/ca.crl");
    expect(byLabel["Certificate policies"]).toBe("2.23.140.1.2.1");
    expect(details.warnings).toEqual([]);
  });

  test("says when it is valid, expired, not yet valid, or about to expire, as of the time it is judged", async () => {
    const { certificate } = await selfSigned("www.example.com", { from: daysFromNow(-100), to: daysFromNow(-3), extensions: [names("www.example.com")] });
    expect((await certificateOf(certificatePem(certificate))).validity).toMatchObject({ status: "expired", days: 3 });
    const future = (await selfSigned("www.example.com", { from: daysFromNow(5), to: daysFromNow(95), extensions: [names("www.example.com")] })).certificate;
    expect((await certificateOf(certificatePem(future))).validity).toMatchObject({ status: "not-yet-valid", days: 5 });
    const soon = (await selfSigned("www.example.com", { from: daysFromNow(-60), to: daysFromNow(7), extensions: [names("www.example.com")] })).certificate;
    const details = await certificateOf(certificatePem(soon));
    expect(details.validity).toMatchObject({ status: "valid", days: 7 });
    expect(details.warnings).toEqual(["It expires in 7 days."]);
    // The same certificate, judged a month on.
    expect((await certificateOf(certificatePem(soon), daysFromNow(30))).validity.status).toBe("expired");
  });

  test("warns of a SHA-1 signature, and of no subject alternative names on a certificate that is not a CA", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const { certificate } = await selfSigned("old.example.com", { keys, signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" }, extensions: [] });
    const details = await certificateOf(certificatePem(certificate));
    expect(details.signature.algorithm).toBe("RSA PKCS#1 v1.5 with SHA-1");
    expect(details.warnings.join(" ")).toContain("SHA-1");
    expect(details.warnings.join(" ")).toContain("no subject alternative names");
  });

  test("says a self-issued certificate whose signature was changed does not verify", async () => {
    const { certificate } = await selfSigned();
    const bytes = new Uint8Array(certificate.rawData.slice(0));
    bytes[bytes.length - 3] = ~bytes[bytes.length - 3]! & 0xff;
    expect((await certificateOf(x509.PemConverter.encode(bytes.buffer, "CERTIFICATE"))).signature.check).toBe("invalid");
  });

  test("reads an ML-DSA-65 certificate, whose signature the browser can check itself", async () => {
    const pem = readFileSync(new URL("./fixtures/viewer/ml-dsa-65.crt.pem", import.meta.url), "utf8");
    const details = await certificateOf(pem, new Date("2030-01-01T00:00:00Z"));
    expect(details.key.algorithm).toBe("ml-dsa-65");
    expect(details.signature).toEqual({ algorithm: "ML-DSA-65", check: "valid" });
    expect(details.names).toEqual([{ type: "DNS", value: "pq.example.com", wildcard: false }]);
    // The path a browser with no ML-DSA in WebCrypto takes.
    const certificate = new x509.X509Certificate(pem);
    expect(verifyMlDsaCertificate(certificate.rawData, certificate.publicKey.rawData)).toBe(true);
    const damaged = certificate.rawData.slice(0);
    const view = new Uint8Array(damaged);
    view[damaged.byteLength - 10] = ~view[damaged.byteLength - 10]! & 0xff;
    expect(verifyMlDsaCertificate(damaged, certificate.publicKey.rawData)).toBe(false);
  });

  test("says why text that is not a certificate cannot be read", async () => {
    expect((await parseCertificateDetails("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")).ok).toBe(false);
  });
});

describe("readPkiText", () => {
  const csr = async (name = "a.example.com") => (await generateCsr({ keyAlgorithm: "ecdsa-p256", names: [name] })).csrPem;

  test("takes the PEM of a CSR, however the whitespace was damaged, as one clean block", async () => {
    const csrPem = await csr();
    const read = readPkiText(`\n\n  ${csrPem.replace(/\n/g, " ")}  \n`);
    expect(read).toEqual({ kind: "items", items: [{ kind: "csr", pem: csrPem.trim() }] });
  });

  test("takes the base64 of a CSR or a certificate that lost its header and footer, and says which it is", async () => {
    const csrPem = await csr();
    const { certificate } = await selfSigned();
    const bare = (pem: string) => pem.split("\n").filter((line) => !line.startsWith("-----")).join("");
    expect(readPkiText(bare(csrPem))).toEqual({ kind: "items", items: [{ kind: "csr", pem: csrPem.trim() }] });
    expect(readPkiText(bare(certificate.toString("pem")))).toEqual({ kind: "items", items: [{ kind: "certificate", pem: certificate.toString("pem").trim() }] });
  });

  test("takes the older NEW CERTIFICATE REQUEST label", async () => {
    const csrPem = await csr();
    expect(readPkiText(csrPem.replaceAll("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"))).toEqual({ kind: "items", items: [{ kind: "csr", pem: csrPem.trim() }] });
  });

  test("takes a certificate, and says it is one without being told", async () => {
    const { certificate } = await selfSigned();
    const read = readPkiText(certificate.toString("pem"));
    expect(read).toEqual({ kind: "items", items: [{ kind: "certificate", pem: certificate.toString("pem").trim() }] });
  });

  test("takes every CSR and certificate in a file, in order, and nothing else in it", async () => {
    const a = await csr("a.example.com");
    const { certificate: first } = await selfSigned("first");
    const { certificate: second } = await selfSigned("second");
    const publicKey = new x509.Pkcs10CertificateRequest(a).publicKey.toString("pem");
    const read = readPkiText(`${first.toString("pem")}\n${publicKey}\n${second.toString("pem")}\n${a}`);
    expect(read).toMatchObject({ kind: "items" });
    expect(read?.kind === "items" && read.items.map((item) => item.kind)).toEqual(["certificate", "certificate", "csr"]);
  });

  test("refuses a private key and says to clear it, even beside a CSR or a certificate", async () => {
    const { csrPem, keyPem } = await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["a.example.com"] });
    const { certificate } = await selfSigned();
    for (const text of [keyPem, `${csrPem}\n${keyPem}`, `${certificate.toString("pem")}\n${keyPem}`, keyPem.replace("PRIVATE KEY", "RSA PRIVATE KEY")]) {
      expect(readPkiText(text)).toMatchObject({ kind: "refused", clear: true });
    }
  });

  test("knows a private key by its header, whatever its kind, and a certificate or a CSR is not one", async () => {
    const { csrPem, keyPem } = await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["a.example.com"] });
    const { certificate } = await selfSigned();
    for (const label of ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"]) expect(containsPrivateKey(`-----BEGIN ${label}-----\nMIG`)).toBe(true);
    expect(containsPrivateKey(`${certificate.toString("pem")}\n${keyPem}`)).toBe(true);
    expect(containsPrivateKey(csrPem)).toBe(false);
    expect(containsPrivateKey(certificate.toString("pem"))).toBe(false);
  });

  test("names what else it is when it is neither", async () => {
    const publicKey = new x509.Pkcs10CertificateRequest(await csr()).publicKey.toString("pem");
    const read = readPkiText(publicKey);
    expect(read).toMatchObject({ kind: "refused", clear: false });
    expect(read?.kind === "refused" && read.problem).toContain("public key, not a CSR or a certificate");
  });

  test("says nothing of nothing, and refuses prose and text far larger than a chain", () => {
    expect(readPkiText("  \n ")).toBeNull();
    expect(readPkiText("hello there")).toMatchObject({ kind: "refused" });
    expect(readPkiText("A".repeat(MAX_CSR_LENGTH + 1))).toMatchObject({ kind: "refused" });
  });

  test("holds the same size limit as the server", () => {
    expect(MAX_CSR_LENGTH).toBe(SERVER_MAX_CSR_LENGTH);
  });
});

describe("textOfPkiFile", () => {
  test("makes PEM of a DER CSR, which then reads as a CSR the server takes", async () => {
    const { csrPem } = await generateCsr({ keyAlgorithm: "ecdsa-p384", names: ["a.example.com"] });
    const der = new Uint8Array(new x509.Pkcs10CertificateRequest(csrPem).rawData);
    expect(kindOfDer(der)).toBe("csr");
    const read = readPkiText(textOfPkiFile(der));
    expect(read).toEqual({ kind: "items", items: [{ kind: "csr", pem: csrPem.trim() }] });
    expect((await parseCsr(read?.kind === "items" ? read.items[0]!.pem : "")).keyAlgorithm).toBe("ecdsa-p384");
  });

  test("makes PEM of a DER certificate, whether its version is 3 or 1", async () => {
    const { certificate } = await selfSigned();
    const der = new Uint8Array(certificate.rawData);
    expect(kindOfDer(der)).toBe("certificate");
    expect(readPkiText(textOfPkiFile(der))).toEqual({ kind: "items", items: [{ kind: "certificate", pem: certificate.toString("pem").trim() }] });
    // A version 1 certificate has no [0] version: its TBS starts with the serial number.
    const v1 = Uint8Array.from([0x30, 0x0b, 0x30, 0x04, 0x02, 0x02, 0x01, 0x00, 0x30, 0x00, 0x03, 0x00]);
    expect(kindOfDer(v1)).toBe("certificate");
  });

  test("leaves a text file, and bytes that are neither, as they are", () => {
    expect(textOfPkiFile(new TextEncoder().encode("-----BEGIN CERTIFICATE REQUEST-----"))).toBe("-----BEGIN CERTIFICATE REQUEST-----");
    expect(kindOfDer(Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x05]))).toBeNull();
  });
});

describe("conversionsOf", () => {
  const certificateItem = async (name = "ca.example.com"): Promise<PkiItem> => ({ kind: "certificate", pem: (await selfSigned(name)).certificate.toString("pem").trim() });
  const csrItem = async (): Promise<PkiItem> => ({ kind: "csr", pem: (await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["a.example.com"] })).csrPem.trim() });
  const make = (items: PkiItem[], format: ConversionFormat) => conversionsOf(items).find((conversion) => conversion.format === format)!.make();

  test("offers a certificate PEM, DER, base64 and PKCS#7, and a CSR the first three", async () => {
    expect(conversionsOf([await certificateItem()]).map((c) => c.format)).toEqual(["pem", "der", "base64", "pkcs7-pem", "pkcs7-der"]);
    expect(conversionsOf([await csrItem()]).map((c) => c.format)).toEqual(["pem", "der", "base64"]);
    expect(conversionsOf([])).toEqual([]);
  });

  test("writes the same bytes: DER and PEM read back as the CSR or certificate they came from", async () => {
    for (const item of [await certificateItem(), await csrItem()]) {
      const der = make([item], "der") as Uint8Array;
      expect(kindOfDer(der)).toBe(item.kind);
      expect(readPkiText(textOfPkiFile(der))).toEqual({ kind: "items", items: [item] });
      expect(readPkiText(make([item], "pem") as string)).toEqual({ kind: "items", items: [item] });
      // One line, and what the viewer reads when the header and footer were lost.
      const base64 = (make([item], "base64") as string).trimEnd();
      expect(base64).not.toContain("\n");
      expect(readPkiText(base64)).toEqual({ kind: "items", items: [item] });
    }
  });

  test("keeps a certificate's signature valid through DER", async () => {
    const { certificate } = await selfSigned();
    const der = make([{ kind: "certificate", pem: certificate.toString("pem").trim() }], "der") as Uint8Array;
    expect(await new x509.X509Certificate(der as BufferSource).verify({ date: NOW })).toBe(true);
  });

  test("names the file for what it holds: .csr for a CSR, .p7b for a bundle, .der for the binary form", async () => {
    const extensions = (item: PkiItem) => Object.fromEntries(conversionsOf([item]).map((c) => [c.format, c.extension]));
    expect(extensions(await csrItem())).toEqual({ pem: ".csr", der: ".der", base64: ".txt" });
    expect(extensions(await certificateItem())).toEqual({ pem: ".pem", der: ".der", base64: ".txt", "pkcs7-pem": ".p7b", "pkcs7-der": ".p7b" });
    expect(conversionsOf([await certificateItem()]).filter((c) => !c.text).map((c) => c.format)).toEqual(["der", "pkcs7-der"]);
  });

  test("makes a PKCS#7 bundle that is read back as the same certificates, in order, from PEM, DER or bare base64", async () => {
    const chain = [await certificateItem("leaf.example.com"), await certificateItem("intermediate.example.com"), await certificateItem("root.example.com")];
    const expected = { kind: "items" as const, items: chain };
    const pem = make(chain, "pkcs7-pem") as string;
    // The label OpenSSL and Windows know, not the one the library writes.
    expect(pem.startsWith("-----BEGIN PKCS7-----\n")).toBe(true);
    expect(readPkiText(pem)).toEqual(expected);
    const der = make(chain, "pkcs7-der") as Uint8Array;
    expect(isPkcs7Der(der)).toBe(true);
    expect(kindOfDer(der)).toBeNull();
    expect(readPkiText(textOfPkiFile(der))).toEqual(expected);
    expect(readPkiText(pem.split("\n").filter((line) => !line.startsWith("-----")).join(""))).toEqual(expected);
    // The library's own PEM label is read too.
    expect(readPkiText(pem.replace(/PKCS7/g, "CMS"))).toEqual(expected);
  });

  test("makes one PEM file of several certificates, and no DER, since a DER file holds one", async () => {
    const chain = [await certificateItem("leaf.example.com"), await certificateItem("root.example.com")];
    expect(conversionsOf(chain).map((c) => c.format)).toEqual(["pem", "pkcs7-pem", "pkcs7-der"]);
    expect(readPkiText(make(chain, "pem") as string)).toEqual({ kind: "items", items: chain });
  });

  test("never bundles a CSR into PKCS#7", async () => {
    expect(conversionsOf([await csrItem()]).map((c) => c.format)).not.toContain("pkcs7-pem");
  });

  test("refuses a PKCS#7 block that holds no certificate, in words", () => {
    const read = readPkiText("-----BEGIN PKCS7-----\nAAAA\n-----END PKCS7-----");
    expect(read).toMatchObject({ kind: "refused", clear: false });
    expect(read?.kind === "refused" && read.problem).toContain("PKCS#7");
  });

  test("makes a file name of what a name has, never one that climbs out of a folder", () => {
    expect(fileBaseOf("*.example.com", "certificate")).toBe("wildcard.example.com");
    expect(fileBaseOf("../../etc/passwd", "certificate")).toBe("etc_passwd");
    expect(fileBaseOf("Example Inc / Ünïcode", "csr")).toBe("Example_Inc_n_code");
    expect(fileBaseOf(null, "csr")).toBe("csr");
    expect(fileBaseOf("***", "certificate")).toBe("certificate");
  });
});

describe("the viewer's imports", () => {
  test("are the X.509 library and the CSR modules alone, and nothing sends anything, so a CSR or certificate read here goes nowhere", () => {
    const allowed = ["@peculiar/x509", "./csr-generator", "./csr-inspect", "./csr-names", "./csr-signature", "./csr-ml-dsa", "./pki-common", "./pki-input"];
    for (const file of DETAILS) {
      const code = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      const imported = [...code.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)].map((m) => m[1]!);
      for (const specifier of imported) expect(allowed).toContain(specifier);
      expect(code).not.toMatch(/\bfetch\b|XMLHttpRequest|sendBeacon|WebSocket|EventSource/);
    }
  });
});
