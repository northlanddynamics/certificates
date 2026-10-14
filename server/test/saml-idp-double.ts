// A SAML identity provider for the SSO tests, built with samlify: it takes the platform's AuthnRequest (HTTP-Redirect)
// and answers with a signed assertion for whoever a test says signs in (HTTP-POST), as Ping or any other IdP would. It is
// not served anywhere: the browser's trip to the IdP is `respond`, and the test posts its answer to the platform itself.
import * as x509 from "@peculiar/x509";
import * as samlify from "samlify";

export interface SamlIdpDouble {
  entityId: string;
  ssoUrl: string;
  /** Its signing certificate, PEM: what an Organization Administrator pastes into the connection. */
  certificate: string;
  /**
   * Answers the platform's sign-in redirect `url` as `email` signing in, for the connection whose service provider is
   * `sp` (its entity ID and ACS URL, as the platform reports them). Returns the form the browser would post to the ACS.
   */
  respond(url: string, sp: { entityId: string; acsUrl: string }, email: string, opts?: { signedBy?: SamlIdpDouble }): Promise<{ action: string; SAMLResponse: string; RelayState: string }>;
  /** @internal */
  idp(entityId?: string): ReturnType<typeof samlify.IdentityProvider>;
}

// The platform validates the XML itself; here it only needs to be well-formed enough for samlify.
samlify.setSchemaValidator({ validate: async () => "skipped" });

async function selfSigned(name: string) {
  const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const now = Date.now();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: `CN=${name}`,
    notBefore: new Date(now - 24 * 3600_000),
    notAfter: new Date(now + 365 * 24 * 3600_000),
    keys,
    signingAlgorithm: alg,
  });
  const pkcs8 = Buffer.from(await crypto.subtle.exportKey("pkcs8", keys.privateKey)).toString("base64");
  const privateKey = `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
  return { certificate: cert.toString("pem"), privateKey };
}

export async function createSamlIdpDouble(entityId = "https://idp.acme.test/saml"): Promise<SamlIdpDouble> {
  const { certificate, privateKey } = await selfSigned("Test IdP");
  const ssoUrl = "https://idp.acme.test/sso";
  const idp = (asEntity = entityId) =>
    samlify.IdentityProvider({
      entityID: asEntity,
      privateKey,
      signingCert: certificate,
      singleSignOnService: [{ Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: ssoUrl }],
      nameIDFormat: ["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"],
    });
  const double: SamlIdpDouble = {
    entityId,
    ssoUrl,
    certificate,
    idp,
    async respond(url, spInfo, email, opts = {}) {
      const request = new URL(url);
      if (`${request.origin}${request.pathname}` !== ssoUrl) throw new Error(`not this IdP's SSO URL: ${url}`);
      const sp = samlify.ServiceProvider({
        entityID: spInfo.entityId,
        wantAssertionsSigned: true,
        assertionConsumerService: [{ Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: spInfo.acsUrl }],
      });
      const signer = (opts.signedBy ?? double).idp(entityId);
      const query = Object.fromEntries(request.searchParams);
      const parsed = await signer.parseLoginRequest(sp, "redirect", { query, octetString: request.search.slice(1) });
      const relayState = request.searchParams.get("RelayState") ?? "";
      const response = (await signer.createLoginResponse(sp, parsed as unknown as Parameters<ReturnType<typeof samlify.IdentityProvider>["createLoginResponse"]>[1], "post", { email }, { relayState })) as { entityEndpoint: string; context: string };
      return { action: response.entityEndpoint, SAMLResponse: response.context, RelayState: relayState };
    },
  };
  return double;
}
