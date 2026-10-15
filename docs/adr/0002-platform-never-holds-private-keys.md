# The platform never holds private keys

For TLS certificates, Key Custody is either the Owner (who submits a CSR) or an Agent (which generates the key and submits a CSR). The platform never generates, stores or relays a private key, even for teams that would find a downloadable key bundle convenient, so that a breach of the platform exposes no keys. When a key must reach several Endpoints, the Agent that generated it distributes it via a Deployment Script; it is never sent to the platform.

The same principle applies to the secrets the platform must hold (DNS Provider credentials, ACME account keys, EAB secrets): they are write-only and can be replaced or tested but never read back by anyone, including Organization Administrators and impersonating Platform Operators.

## Addendum: the CSR Generator

The web app's code runs in the user's browser, and what the platform serves is not the platform. The CSR Generator makes a key pair and a CSR there, with WebCrypto, and never sends the key anywhere: it has no route on the server, and only the CSR is submitted, to the forms that already took one. The key is offered to the user to download or copy, and is dropped from the page's state when they leave it or make another. The platform still never generates, stores or relays a private key.

## Addendum: relayed DNS Provider credentials

A DNS Provider that Agents relay is run beside DNS the platform cannot reach, so its credentials must reach the Agent that runs an operation. They stay write-only for people. The platform puts them into a work item only at the moment its Agent is given it, over the Agent's mTLS channel, for that operation alone: they are never stored in the work item, shown by any API, written to an Audit Event or logged, and an Agent that is revoked, or an item that has waited too long, is given none. The Agent holds them in memory for the operation and keeps nothing. Delivery is not itself an Audit Event; the operations that cause it (a connection test, an Issuance) are recorded.

## Amendment: Private CA keys

A Private CA's signing keys are held only as non-exportable keys in a KMS, and the SCEP RA key as a wrapped software key; see [ADR 0007](0007-private-ca-keys-are-held-in-a-kms.md). The platform still never holds a Managed Certificate's key or a device's.
