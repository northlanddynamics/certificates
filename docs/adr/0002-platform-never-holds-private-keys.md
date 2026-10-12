# The platform never holds private keys

For TLS certificates, Key Custody is either the Owner (who submits a CSR) or an Agent (which generates the key and submits a CSR). The platform never generates, stores or relays a private key, even for teams that would find a downloadable key bundle convenient, so that a breach of the platform exposes no keys. When a key must reach several Endpoints, the Agent that generated it distributes it via a Deployment Script; it is never sent to the platform.

The same principle applies to the secrets the platform must hold (DNS Provider credentials, ACME account keys, EAB secrets): they are write-only and can be replaced or tested but never read back by anyone, including Organization Administrators and impersonating Platform Operators.

## Addendum: the CSR Generator

The web app's code runs in the user's browser, and what the platform serves is not the platform. The CSR Generator makes a key pair and a CSR there, with WebCrypto, and never sends the key anywhere: it has no route on the server, and only the CSR is submitted, to the forms that already took one. The key is offered to the user to download or copy, and is dropped from the page's state when they leave it or make another. The platform still never generates, stores or relays a private key.
