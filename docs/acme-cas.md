# ACME CAs

An ACME CA is a Certificate Authority the platform obtains Certificates from over ACME: a directory URL, and what is needed to register an account there. A Managed Certificate whose issuer is an ACME CA is issued through the Organization's ACME Account with that CA, and its Issuance fails until there is one. Each ACME CA needs an account of its own, at most one per Organization.

Only Organization Administrators see the ACME CAs' configuration and the ACME Accounts, under Administration → Integrations → ACME accounts in the web app or `/api/organizations/{orgId}/acme-cas` and `/api/organizations/{orgId}/acme-accounts`; they alone may register, change, delete and test them. Anyone in the Organization may list the ACME CAs, by name and Environment Tag and whether the Organization has an account with each, to choose one for a Managed Certificate.

## The built-in ACME CAs

Two are built in, the same for every Organization, and cannot be changed or deleted:

| ACME CA | Id | Directory URL | Environment Tag |
|---|---|---|---|
| Let's Encrypt Staging | `letsencrypt-staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` | `staging` |
| Let's Encrypt Production | `letsencrypt-production` | `https://acme-v02.api.letsencrypt.org/directory` | `production` |

Their configuration is shown, read-only, on the ACME accounts page and in its **Register an account** dialog. Let's Encrypt Staging is the default issuer of a new Managed Certificate, so that an Issuance is tried there before production, where Let's Encrypt rate-limits; its Certificates are not trusted by browsers.

## Registering an ACME Account

On the ACME accounts page, **Register an account** offers each ACME CA the Organization has no account with yet, and **A custom ACME CA…**:

- **With a built-in ACME CA**, give an optional contact email and agree to the CA's terms of service on the Organization's behalf (`POST /api/organizations/{orgId}/acme-accounts` with `acmeCaId`, `contactEmail` and `termsOfServiceAgreed: true`). Register with Let's Encrypt Staging first.
- **With a custom ACME CA**, the CA is added and its account registered in the same step, below.

Either way the platform makes the account's key and keeps it as a Secret; it is never shown. **Test** on an account checks that the CA still accepts its key. If the key was changed at the CA, `PUT .../acme-accounts/{accountId}/key` replaces it, once the CA accepts the new one for the account.

## Adding a custom ACME CA

For an ACME CA other than Let's Encrypt, such as an internal step-ca, an enterprise ACME service or a commercial CA, choose **A custom ACME CA…** and give (`POST /api/organizations/{orgId}/acme-cas`):

- **Name**: unique within the Organization, the built-in ones' names included.
- **Directory URL**: where the CA serves its ACME directory. It must be https, and must not be at a loopback or link-local address (which holds the cloud metadata address); a private address is fine, for an ACME server inside your network. It is checked when the CA is added and again each time the platform connects to it, by the addresses its name resolves to then. The platform needs to reach it over HTTPS with a certificate the server trusts; its network rules are unchanged, so reaching the CA is a deployment matter.
- **Environment Tag** (optional), below.
- **External Account Binding** (optional), below.
- **Contact email** (optional), and agreement to the CA's terms of service.

**Add and register** registers the Organization's ACME Account with the CA and saves the CA and the account only once the CA has accepted it. A CA that refuses is reported with its reason, one that does not answer is reported too, and either way nothing is saved, so there is never a custom ACME CA that cannot issue.

Issuance from a custom ACME CA runs as it does from Let's Encrypt: DCV is DNS-01, through the Organization's DNS Providers and Validation Zones and its DCV Rules, with no settings of the CA's own. Renewals run the same way; where the CA's directory offers ACME Renewal Information (ARI), Renewal follows the time it suggests. Revoking a Certificate it issued asks the CA; a CA whose directory offers no revocation fails with an error saying so, and the Certificate is not recorded as revoked.

## External Account Binding

Some CAs, commercial ones especially, register only accounts bound to an account you already hold with them. They give you a **key id** and an **HMAC key** (base64url, or plain base64 as some CAs give it) for External Account Binding; give both, or neither. The HMAC key is kept as a Secret: it is never shown again, nor written to an Audit Event. The key id is shown with the CA.

## The Environment Tag

An ACME CA's Environment Tag is `staging`, `production` or none: a label of what it is for, which you set to tell your colleagues. It changes nothing about how the CA issues. It is shown as a badge beside the CA's name, in the ACME accounts list (as **Tag**), in the issuer picker of a new Managed Certificate (which can be filtered by tag) and in the Managed Certificates list (filtered by **Environment tag**, the API's `tag` filter). The built-in ones carry fixed tags. A past Certificate shows its ACME CA's tag as it is now, so retagging a CA retags its history.

## Changing a custom ACME CA

**Edit** on a custom ACME CA changes its name, its Environment Tag and its account's contact email (`PATCH /api/organizations/{orgId}/acme-cas/{acmeCaId}`). A new contact email is sent to the CA first and saved only once the CA accepts it.

Its directory URL and External Account Binding are fixed once it is added, so that a live account cannot be pointed somewhere else. To change them, delete the ACME CA and add it again.

## Deleting a custom ACME CA

**Delete** removes a custom ACME CA, the Organization's account with it, and their Secrets (the account's key and any External Account Binding HMAC key); the account is left as it is at the CA. It is refused while any Managed Certificate, archived ones included, or any Certificate refers to the CA, so that their history and revocation keep working. A custom ACME CA that has issued anything therefore stays; retag or rename it instead.

## Audit

Adding a custom ACME CA records `acme_ca.created` and its account's `acme_account.created` in the same change; registering with a built-in one records `acme_account.created`; replacing an account's key records `acme_account.key_replaced`; editing a custom one records `acme_ca.updated` and deleting it `acme_ca.deleted`. Their detail is in [audit-events.md](audit-events.md).
