// An ACME directory that is Pebble's with some of its endpoints left out, for a custom ACME CA that offers less than
// Pebble does (no revocation, no ARI). Only the directory is served here: every URL it lists is still Pebble's, so the
// account, its orders and its Certificates are Pebble's own. It is served over https, from a root of its own that the
// platform's ACME client is given to trust beside Pebble's.
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";

export interface DirectoryProxy {
  /** The root its TLS certificate is signed by (PEM). */
  readonly ca: string;
  /** Where it is served, as a directory URL's origin. */
  readonly origin: string;
  /** A directory URL that serves Pebble's directory without the entries `omit`, such as `revokeCert` or `renewalInfo`. */
  without(...omit: string[]): string;
  stop(): Promise<void>;
}

const pem = (label: string, der: ArrayBuffer) => `-----BEGIN ${label}-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----\n`;

export async function startDirectoryProxy({ pebbleDirectory, pebbleCa }: { pebbleDirectory: string; pebbleCa: string }): Promise<DirectoryProxy> {
  const crypto = webcrypto as unknown as Crypto;
  const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
  // TLS goes by the real clock, not the harness's.
  const notBefore = new Date(Date.now() - 86_400_000);
  const notAfter = new Date(Date.now() + 365 * 86_400_000);
  const rootKeys = (await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"])) as CryptoKeyPair;
  const root = await x509.X509CertificateGenerator.createSelfSigned(
    {
      name: "CN=Test directory proxy root",
      notBefore,
      notAfter,
      keys: rootKeys,
      signingAlgorithm: algorithm,
      extensions: [new x509.BasicConstraintsExtension(true, undefined, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true)],
    },
    crypto,
  );
  const leafKeys = (await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"])) as CryptoKeyPair;
  const leaf = await x509.X509CertificateGenerator.create(
    {
      subject: "CN=127.0.0.1",
      issuer: root.subject,
      notBefore,
      notAfter,
      publicKey: leafKeys.publicKey,
      signingKey: rootKeys.privateKey,
      signingAlgorithm: algorithm,
      extensions: [
        new x509.BasicConstraintsExtension(false),
        new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
        new x509.SubjectAlternativeNameExtension([{ type: "ip", value: "127.0.0.1" }]),
      ],
    },
    crypto,
  );

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    tls: { cert: leaf.toString("pem"), key: pem("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", leafKeys.privateKey)) },
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname !== "/dir") return new Response("not found", { status: 404 });
      const directory = (await (await fetch(pebbleDirectory, { tls: { ca: pebbleCa } })).json()) as Record<string, unknown>;
      for (const entry of url.searchParams.getAll("without")) delete directory[entry];
      return Response.json(directory);
    },
  });
  const origin = `https://127.0.0.1:${server.port}`;
  return {
    ca: root.toString("pem"),
    origin,
    without: (...omit) => `${origin}/dir?${omit.map((entry) => `without=${encodeURIComponent(entry)}`).join("&")}`,
    stop: () => server.stop(true),
  };
}
