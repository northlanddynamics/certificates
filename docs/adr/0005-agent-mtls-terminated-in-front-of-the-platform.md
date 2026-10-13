# Agents authenticate with mTLS, verified in front of the platform

Superseded by [0006](0006-agents-authenticate-with-a-bearer-credential.md): mTLS needed a terminator that Bun could not replace, so Agents use a bearer credential over ordinary TLS.

Agents prove who they are with a client certificate from a platform-internal CA that issues nothing else (it is not a Private CA). The Agent generates its own key and sends a CSR, so the platform never holds an Agent's key (ADR 0002), and rotates the certificate on its own once a third of its life is left; Agent Registration with a single-use token is the one call that needs no certificate.

Bun's HTTP server does not tell a request handler which client certificate the connection presented, so the platform cannot do the mTLS handshake itself and learn who is calling. The platform is therefore deployed behind a TLS terminator (an ingress, a load balancer, nginx) that requires and verifies the client certificate against the identity CA (`GET /api/agent/identity-ca`) for the `/api/agent/*` routes, and passes the verified certificate on in the `x-client-cert` header (URL-encoded PEM, as nginx's `$ssl_client_escaped_cert`). The platform checks the certificate again itself — signed by the identity CA, valid now, the Agent's current identity (or the one it just replaced), the Agent not revoked — so revoking an Agent takes effect at once, without a revocation list at the terminator.

We chose this over an application-level signature on every request, which would need no terminator but would not be mTLS, and over a separate mTLS listener in another runtime, which would be a second deployable.

Consequences: the terminator must overwrite `x-client-cert` on every request (empty when the client sent no certificate), and the platform's own port must not be reachable except through it, because the header is trusted. A certificate is not a secret, so a header the terminator did not set would let anyone who has seen an Agent's certificate act as that Agent. An Agent that is away longer than its certificate lasts (30 days) cannot rotate and registers again with a new token.

To not rely on the network alone, the platform can be given a secret (`AGENT_GATEWAY_SECRET`) that the terminator sends in `x-agent-gateway-secret` on every request; when it is set, a call that carries an identity without it is refused. Setting it is recommended wherever the platform's port can be reached other than through the terminator.
