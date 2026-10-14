// An OIDC identity provider for the SSO tests: discovery, a token endpoint that checks the client's secret and the PKCE
// verifier, and ID tokens signed with its own key, served on a local port. Its users are whoever a test says signs in:
// `authorize` plays the browser's visit to the authorization endpoint and returns where the IdP sends it back.
import { createHash } from "node:crypto";
import { SignJWT, exportJWK, generateKeyPair } from "jose";

export interface OidcIdentity {
  sub: string;
  email: string;
  name?: string;
}

export interface OidcIdpDouble {
  /** Its issuer, and the origin the platform must trust to fetch from a local address. */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Answers the authorization request at `url` as `identity` signing in: the redirect back to the platform, with the code. */
  authorize(url: string, identity: OidcIdentity): string;
  stop(): void;
}

export async function createOidcIdpDouble(clientId = "platform-client", clientSecret = "platform-client-secret"): Promise<OidcIdpDouble> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const codes = new Map<string, { identity: OidcIdentity; redirectUri: string; challenge: string | null }>();
  let issuer = "";

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/.well-known/openid-configuration") {
        return Response.json({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          token_endpoint_auth_methods_supported: ["client_secret_basic"],
        });
      }
      if (url.pathname === "/jwks") return Response.json({ keys: [jwk] });
      if (url.pathname === "/token" && req.method === "POST") {
        const form = new URLSearchParams(await req.text());
        const basic = (req.headers.get("authorization") ?? "").replace(/^Basic /, "");
        const [id, secret] = Buffer.from(basic, "base64").toString().split(":").map(decodeURIComponent);
        if (id !== clientId || secret !== clientSecret) return Response.json({ error: "invalid_client" }, { status: 401 });
        const grant = codes.get(form.get("code") ?? "");
        codes.delete(form.get("code") ?? "");
        if (!grant || grant.redirectUri !== form.get("redirect_uri")) return Response.json({ error: "invalid_grant" }, { status: 400 });
        const verifier = form.get("code_verifier");
        if (grant.challenge && (!verifier || createHash("sha256").update(verifier).digest("base64url") !== grant.challenge)) {
          return Response.json({ error: "invalid_grant" }, { status: 400 });
        }
        const { sub, email, name = email } = grant.identity;
        const idToken = await new SignJWT({ email, name })
          .setProtectedHeader({ alg: "RS256", kid: "k1" })
          .setIssuer(issuer)
          .setAudience(clientId)
          .setSubject(sub)
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(privateKey);
        return Response.json({ access_token: crypto.randomUUID(), token_type: "Bearer", expires_in: 300, id_token: idToken });
      }
      return new Response("not found", { status: 404 });
    },
  });
  issuer = `http://127.0.0.1:${server.port}`;

  return {
    issuer,
    clientId,
    clientSecret,
    authorize(url, identity) {
      const request = new URL(url);
      if (`${request.origin}${request.pathname}` !== `${issuer}/authorize`) throw new Error(`not this IdP's authorization endpoint: ${url}`);
      if (request.searchParams.get("client_id") !== clientId) throw new Error("unknown client");
      const code = crypto.randomUUID();
      const redirectUri = request.searchParams.get("redirect_uri")!;
      codes.set(code, { identity, redirectUri, challenge: request.searchParams.get("code_challenge") });
      const back = new URL(redirectUri);
      back.searchParams.set("code", code);
      back.searchParams.set("state", request.searchParams.get("state")!);
      return back.toString();
    },
    stop: () => server.stop(true),
  };
}
