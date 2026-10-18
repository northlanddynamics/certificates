// The CSR Generator lives in the web package and runs in the user's browser; these tests run it here, under Bun's
// WebCrypto, and hold it to what the server accepts: a CSR the real parseCsr takes, and names the real normalizeName agrees with.
import { describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createPrivateKey } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CLASSICAL_KEY_ALGORITHMS as KEY_ALGORITHMS, parseCsr, type ClassicalKeyAlgorithm as KeyAlgorithm } from "../src/pki/csr";
import { MAX_NAMES, normalizeName } from "../src/pki/names";
import { defaultHash, generateCsr, hashNote, SIGNATURE_HASHES } from "../../web/src/lib/csr-generator";
import { inspectCsr, matchCsr, opensslCommand, type CsrFacts } from "../../web/src/lib/csr-inspect";

const GENERATOR = new URL("../../web/src/lib/csr-generator.ts", import.meta.url);
const NAME_RULES = new URL("../../web/src/lib/csr-names.ts", import.meta.url);
const INSPECTOR = new URL("../../web/src/lib/csr-inspect.ts", import.meta.url);

describe("generateCsr", () => {
  for (const keyAlgorithm of KEY_ALGORITHMS) {
    test(`a ${keyAlgorithm} CSR is accepted by parseCsr with its names and key algorithm`, async () => {
      const { csrPem, keyPem } = await generateCsr({ keyAlgorithm, names: ["example.com", "*.example.com"], commonName: "example.com" });
      const parsed = await parseCsr(csrPem);
      expect(parsed.keyAlgorithm).toBe(keyAlgorithm);
      expect([...parsed.names].sort()).toEqual(["*.example.com", "example.com"]);
      // The key is unencrypted PKCS#8 and is the one the CSR carries.
      expect(keyPem.startsWith("-----BEGIN PRIVATE KEY-----")).toBe(true);
      const key = createPrivateKey(keyPem);
      expect(key.asymmetricKeyType).toBe(keyAlgorithm.startsWith("rsa") ? "rsa" : "ec");
    }, 60_000);
  }

  test("signs with the chosen hash, and with the key algorithm's default when none is chosen", async () => {
    const names = ["example.com"];
    for (const hash of SIGNATURE_HASHES) {
      for (const keyAlgorithm of ["ecdsa-p256", "rsa-2048"] as const) {
        const { csrPem } = await generateCsr({ keyAlgorithm, names, hash });
        expect(new x509.Pkcs10CertificateRequest(csrPem).signatureAlgorithm.hash.name).toBe(hash);
        await parseCsr(csrPem);
      }
    }
    const signedWith = async (keyAlgorithm: KeyAlgorithm) =>
      new x509.Pkcs10CertificateRequest((await generateCsr({ keyAlgorithm, names })).csrPem).signatureAlgorithm.hash.name;
    expect(await signedWith("ecdsa-p256")).toBe("SHA-256");
    expect(await signedWith("ecdsa-p384")).toBe("SHA-384");
    expect(await signedWith("rsa-3072")).toBe("SHA-256");
    expect(defaultHash("ecdsa-p384")).toBe("SHA-384");
  });

  test("warns softly about SHA-256 with P-384 and about nothing else", () => {
    expect(hashNote("ecdsa-p384", "SHA-256")).toContain("weaker");
    expect(hashNote("ecdsa-p384", "SHA-384")).toBeNull();
    expect(hashNote("rsa-2048", "SHA-256")).toBeNull();
    expect(hashNote("ecdsa-p256", "SHA-256")).toBeNull();
  });

  test("puts the subject details in the subject and leaves empty ones out", async () => {
    const { csrPem } = await generateCsr({
      keyAlgorithm: "ecdsa-p256",
      names: ["a.example.com", "b.example.com"],
      commonName: "b.example.com",
      subject: { organization: "Example Inc", organizationalUnit: "  ", country: "US", state: "", locality: "Minneapolis" },
    });
    const subject = new x509.Pkcs10CertificateRequest(csrPem).subjectName;
    expect(subject.getField("CN")).toEqual(["b.example.com"]);
    expect(subject.getField("O")).toEqual(["Example Inc"]);
    expect(subject.getField("C")).toEqual(["US"]);
    expect(subject.getField("L")).toEqual(["Minneapolis"]);
    expect(subject.getField("OU")).toEqual([]);
    expect(subject.getField("ST")).toEqual([]);
  });

  test("with no CN the subject has none and the names come from the alternative names alone", async () => {
    const { csrPem } = await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["a.example.com"], commonName: null });
    expect(new x509.Pkcs10CertificateRequest(csrPem).subjectName.getField("CN")).toEqual([]);
    expect((await parseCsr(csrPem)).names).toEqual(["a.example.com"]);
  });

  test("a wildcard CN is a name too", async () => {
    const { csrPem } = await generateCsr({ keyAlgorithm: "ecdsa-p256", names: ["*.example.com"], commonName: "*.example.com" });
    expect((await parseCsr(csrPem)).names).toEqual(["*.example.com"]);
  });
});

// What the web reads from a pasted CSR, to say at once whether it fits, must be what parseCsr reads from it.
describe("inspectCsr", () => {
  for (const keyAlgorithm of KEY_ALGORITHMS) {
    test(`reads a ${keyAlgorithm} CSR's key algorithm and names as parseCsr does`, async () => {
      const { csrPem } = await generateCsr({ keyAlgorithm, names: ["www.example.com", "*.example.com"], commonName: "www.example.com" });
      const facts = (await inspectCsr(csrPem)) as CsrFacts;
      const parsed = await parseCsr(csrPem);
      expect(parsed.keyAlgorithm).toBe(facts.keyAlgorithm!);
      expect([...facts.names].sort()).toEqual([...parsed.names].sort());
    }, 60_000);
  }

  test("counts the CN among the names, normalised, as parseCsr does", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=Only.Example.COM",
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "other.example.com" }])],
    });
    const facts = (await inspectCsr(csr.toString("pem"))) as CsrFacts;
    expect([...facts.names].sort()).toEqual([...(await parseCsr(csr.toString("pem"))).names].sort());
  });

  test("says why when the text is not a CSR, and nothing when there is no text", async () => {
    expect(await inspectCsr("")).toBeNull();
    expect(await inspectCsr("-----BEGIN CERTIFICATE REQUEST-----\nnot base64\n-----END CERTIFICATE REQUEST-----")).toContain("not a PEM CSR");
  });

  test("matchCsr names what is missing, what was not asked for, and a different key algorithm", async () => {
    const { csrPem } = await generateCsr({ keyAlgorithm: "rsa-2048", names: ["a.example.com", "b.example.com"] });
    const facts = (await inspectCsr(csrPem)) as CsrFacts;
    expect(matchCsr(facts, ["B.example.com", "a.example.com"], "rsa-2048")).toEqual({ missing: [], extra: [], algorithmOk: true, ok: true });
    expect(matchCsr(facts, ["a.example.com", "c.example.com"], "ecdsa-p256")).toEqual({ missing: ["c.example.com"], extra: ["b.example.com"], algorithmOk: false, ok: false });
  });
});

// The command the web offers for making the key on the user's own machine must make a CSR the server takes.
describe("opensslCommand", () => {
  for (const keyAlgorithm of ["ecdsa-p256", "ecdsa-p384", "rsa-2048"] as const) {
    test(`makes a ${keyAlgorithm} key and a CSR parseCsr accepts with exactly the names`, async () => {
      const names = ["www.example.com", "*.example.com"];
      const dir = mkdtempSync(join(tmpdir(), "openssl-command-"));
      try {
        const run = Bun.spawnSync(["sh", "-c", opensslCommand(names, keyAlgorithm)], { cwd: dir, stderr: "pipe" });
        expect(run.exitCode).toBe(0);
        const parsed = await parseCsr(readFileSync(join(dir, "www.example.com.csr.pem"), "utf8"));
        expect(parsed.keyAlgorithm).toBe(keyAlgorithm);
        expect([...parsed.names].sort()).toEqual([...names].sort());
        expect(readFileSync(join(dir, "www.example.com.key.pem"), "utf8")).toContain("PRIVATE KEY");
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }, 60_000);
  }

  test("leaves out the CN when no name fits in one", async () => {
    const long = `${"a".repeat(60)}.${"b".repeat(10)}.example.com`;
    const dir = mkdtempSync(join(tmpdir(), "openssl-command-"));
    try {
      const run = Bun.spawnSync(["sh", "-c", opensslCommand([long], "ecdsa-p256")], { cwd: dir, stderr: "pipe" });
      expect(run.exitCode).toBe(0);
      expect((await parseCsr(readFileSync(join(dir, `${long}.csr.pem`), "utf8"))).names).toEqual([long]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// The web package shares no code with the server, so its name rules are a copy, held to the server's here.
describe("the web name rules", () => {
  const FIXTURES = [
    "example.com", "Example.COM", " example.com ", "example.com.", "*.example.com", "*.*.example.com", "*example.com", "a*.example.com",
    "localhost", "single", "10.0.0.1", "1.2.3", "1.2.3.4.5", "::1", "[::1]", "a_b.example.com", "_dmarc.example.com", "-a.example.com", "a-.example.com",
    "a--b.example.com", "xn--bcher-kva.example", "bücher.example", "a".repeat(63) + ".com", "a".repeat(64) + ".com", ("a".repeat(60) + ".").repeat(4) + "com",
    "", " ", ".", ".example.com", "example..com", "ex ample.com", "https://example.com", "example.com/path", "example.com:443", "user@example.com", "*.", "*",
  ];

  test("agree with normalizeName on every fixture", async () => {
    const { normalizeName: web } = await import("../../web/src/lib/csr-names");
    for (const name of FIXTURES) expect({ name, result: web(name) }).toEqual({ name, result: normalizeName(name) });
  });

  test("count at most MAX_NAMES, and report each problem inline", async () => {
    const { MAX_NAMES: webMax, nameProblems } = await import("../../web/src/lib/csr-names");
    expect(webMax).toBe(MAX_NAMES);
    expect(nameProblems(["example.com", "*.example.com"])).toEqual([]);
    expect(nameProblems([])).toEqual(["Enter at least one name."]);
    expect(nameProblems(["10.0.0.1"])[0]).toContain("10.0.0.1");
    expect(nameProblems(["a_b.example.com"])[0]).toContain("a_b.example.com");
    expect(nameProblems(Array.from({ length: MAX_NAMES + 1 }, (_, i) => `h${i}.example.com`))[0]).toContain(String(MAX_NAMES));
    expect(nameProblems(["example.com", "EXAMPLE.com"])).toEqual([]);
  });
});

describe("the generator's imports", () => {
  test("are the X.509 library and the name rules alone, and nothing sends anything, so there is nowhere for the key to go", () => {
    const allowed = ["@peculiar/x509", "./csr-names", "./csr-generator"];
    for (const file of [GENERATOR, NAME_RULES, INSPECTOR]) {
      const code = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      const imported = [...code.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)].map((m) => m[1]!);
      for (const specifier of imported) expect(allowed).toContain(specifier);
      expect(code).not.toMatch(/\bfetch\b|XMLHttpRequest|sendBeacon|WebSocket|EventSource/);
    }
  });
});
