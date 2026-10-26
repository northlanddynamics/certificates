// The setup guides and the screens beside them work out in the browser some of what the server decides; the web package
// shares no code with the server, so those copies are held to the server's here.
import { describe, expect, test } from "bun:test";
import { publicationUrls } from "../src/private-ca/crl";
import { publicationProblems, publicationUrls as webPublicationUrls } from "../../web/src/lib/pki-publication";

describe("where a Private CA's Certificates send relying parties, as the web shows it", () => {
  for (const base of ["http://pki.example.com", "http://pki.example.com/", "http://pki.example.com//", "https://certs.example.com/base"]) {
    for (const signer of ["root", "issuing"] as const) {
      test(`agrees with the server for ${signer} under ${base}`, () => {
        expect(webPublicationUrls(base, { signer, id: "0b6d5d3e" })).toEqual(publicationUrls(base, { signer, id: "0b6d5d3e" }));
      });
    }
  }

  test("finds nothing wrong with a plain-HTTP base URL the operator set, and says what is wrong otherwise", () => {
    expect(publicationProblems({ baseUrl: "http://pki.example.com", configured: true })).toEqual([]);
    expect(publicationProblems({ baseUrl: "HTTPS://certs.example.com", configured: true }).map((p) => p.title)).toEqual(["The PKI base URL is HTTPS"]);
    expect(publicationProblems({ baseUrl: "http://localhost:3000", configured: false }).map((p) => p.title)).toEqual(["The PKI base URL was never set"]);
  });
});
