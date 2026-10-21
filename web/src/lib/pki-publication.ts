// Where the Private CAs publish, as the web shows it. It imports nothing, so server/test/setup-guides-web.test.ts can hold
// it to the server's.

/** Where relying parties fetch what the Private CAs publish: every Certificate they sign names it. */
export interface PkiPublication {
  baseUrl: string;
  /** Whether the platform's operator set it; when not, it is where the API is served. */
  configured: boolean;
}

/**
 * Where a CA's CRL and certificate are served, which every certificate it signs names: a copy of `publicationUrls` in
 * server/src/private-ca/crl.ts (which imports the database), held to it by server/test/setup-guides-web.test.ts.
 */
export function publicationUrls(pkiBaseUrl: string, { signer, id }: { signer: "root" | "issuing"; id: string }) {
  const base = `${pkiBaseUrl.replace(/\/+$/, "")}/pki/${signer === "issuing" ? "issuing-cas" : "roots"}/${id}`;
  return { crl: `${base}/ca.crl`, certificate: `${base}/ca.crt` };
}

/** What is wrong with where the Private CAs publish, as far as the platform can tell; nothing when it looks right. */
export function publicationProblems({ baseUrl, configured }: PkiPublication): { title: string; detail: string }[] {
  return [
    ...(/^https:/i.test(baseUrl)
      ? [{ title: "The PKI base URL is HTTPS", detail: "Relying parties that check revocation need plain HTTP, and many will refuse Certificates whose CRL is only served over HTTPS. Ask whoever runs the platform to change it before you issue." }]
      : []),
    ...(!configured
      ? [{ title: "The PKI base URL was never set", detail: "It is only the address you reach the platform at, which relying parties may not. Ask whoever runs the platform to set a public, plain-HTTP address before you issue." }]
      : []),
  ];
}
