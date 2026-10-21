# Spec: Custom ACME CAs

Status: ready-for-agent

## Problem Statement

The platform can obtain Certificates from Let's Encrypt only. An ACME Account is keyed by the Organization and an environment, staging or production, and both environments are Let's Encrypt. Organizations that run or buy from another ACME CA (an internal CA such as step-ca, an enterprise ACME service, a commercial CA that takes External Account Binding) cannot use the platform for it, so they keep a second tool for those Certificates. An Organization Administrator also cannot see what the Let's Encrypt configuration is: the directory the platform talks to is hidden.

## Solution

An **ACME CA** becomes a thing in its own right: a directory URL plus the settings needed to register an account with it. Let's Encrypt Staging and Let's Encrypt Production are built in, the same for every Organization and shown read-only. An Organization Administrator can also create custom ACME CAs of the Organization's own: a name, an https directory URL, optional External Account Binding, a contact email and an environment tag. Creating one registers the Organization's ACME Account with it in the same step.

When someone creates a Managed Certificate they pick between every ACME CA the Organization can use, and the Private CAs' Issuing CAs, as today.

The environment tag (`staging`, `production`, or none) is a label the administrator sets to record intent. It changes no behavior; it is shown as a badge and can be filtered on.

## User Stories

1. As an Organization Administrator, I want Let's Encrypt Staging and Production offered out of the box, so that I can start issuing without configuring a CA.
2. As an Organization Administrator, I want the built-in Let's Encrypt configuration shown but not editable, so that I can see what the platform talks to without being able to break it.
3. As an Organization Administrator, I want to register an account with a built-in CA by giving only a contact email and agreeing to the terms, so that registration stays as simple as it is today.
4. As an Organization Administrator, I want to add a custom ACME CA by name and directory URL, so that I can issue from a CA other than Let's Encrypt.
5. As an Organization Administrator, I want creating a custom CA to register the account with it in the same step, so that I never hold a saved CA that cannot issue.
6. As an Organization Administrator, I want nothing saved when the CA refuses registration, so that I do not clean up half-made records.
7. As an Organization Administrator, I want to give an External Account Binding key id and HMAC key, so that I can register with CAs that require one.
8. As an Organization Administrator, I want the HMAC key kept as a Secret that nobody can read back, so that it cannot leak through the platform.
9. As an Organization Administrator, I want a clear message when a directory URL is not https or points at loopback or link-local addresses, so that I know why it was refused.
10. As an Organization Administrator, I want internal CAs on private address ranges allowed, so that I can use an ACME server inside my network.
11. As an Organization Administrator, I want several custom CAs under unique names, so that I can use more than one external CA.
12. As an Organization Administrator, I want to tag a CA `staging` or `production`, so that my colleagues can see what it is for.
13. As an Organization Administrator, I want the tag to change nothing about how issuance works, so that I can retag without risk.
14. As an Organization Administrator, I want to rename a custom CA and change its contact email and tag, so that I can keep it tidy without recreating it.
15. As an Organization Administrator, I want the directory URL and External Account Binding fixed after creation, so that a live account cannot be silently pointed somewhere else.
16. As an Organization Administrator, I want to delete a custom CA that nothing uses, so that I can remove one I added by mistake.
17. As an Organization Administrator, I want deletion refused while a Managed Certificate or Certificate refers to the CA, so that history and revocation keep working.
18. As an Organization Administrator, I want a Test button on each account, built-in or custom, so that I can check the CA still accepts the account's key.
19. As an Organization Administrator, I want each creation, edit, deletion and registration written to the audit log, so that changes to where Certificates come from can be reviewed.
20. As a Managed Certificate creator, I want every ACME CA and Issuing CA listed in one picker, so that I choose the issuer in one place.
21. As a Managed Certificate creator, I want Let's Encrypt Staging selected by default, so that I try an Issuance before production, as today.
22. As a Managed Certificate creator, I want a CA with no account for my Organization shown but disabled, with the reason, so that I understand why it cannot be chosen.
23. As a Managed Certificate creator, I want each ACME CA's tag shown beside its name, so that I can tell staging from production at a glance.
24. As a Managed Certificate creator, I want to filter the picker by tag, so that I find the right CA in a long list.
25. As a Managed Certificate owner, I want renewals from a custom CA to run like renewals from Let's Encrypt, so that nothing needs manual handling.
26. As a Managed Certificate owner, I want renewal timing to follow the CA's ARI when the CA offers it, so that Certificates renew when the CA asks.
27. As an Organization Administrator, I want a clear error when a CA has no revocation endpoint and I revoke a Certificate it issued, so that I know the platform could not do it.
28. As a user who is not an Organization Administrator, I want not to see ACME CAs or their configuration, so that the settings stay with administrators.
29. As an Organization Administrator, I want existing Let's Encrypt accounts, Managed Certificates and Certificates to keep working after the change, so that nothing is lost in the move.
30. As an agent operator, I want the agent contract to refer to the ACME CA by id, so that agents learn which CA issued a Certificate.

## Implementation Decisions

- **ACME CA** is a new term in the glossary. A built-in ACME CA is defined in code with a stable id (`letsencrypt-staging`, `letsencrypt-production`), is shared by all Organizations, and cannot be changed. A custom ACME CA is a per-Organization record with a unique name. **ACME Account** is reworded to belong to one ACME CA.
- The ACME Account is keyed by Organization and ACME CA: at most one per pair. It replaces the `environment` column.
- A Managed Certificate's issuer becomes `{kind: "acme", acmeCaId}` in place of `{kind: "acme", environment}`. A Certificate records the ACME CA and ACME Account it came from. The `environment` columns on Managed Certificate and Certificate are dropped; the tag is read through the CA, so a past Certificate shows the CA's current tag.
- A migration maps `staging` and `production` to the two built-in ids across ACME Account, Managed Certificate and Certificate. There is no compatibility alias: the API and the agent contract carry only `acmeCaId`. One short ADR records this breaking, hard-to-reverse change.
- A custom ACME CA has: a name, an https directory URL, an optional External Account Binding (key id and HMAC key), a contact email and an environment tag. The HMAC key is a Secret, written but never read back.
- The environment tag is `staging`, `production` or none. Built-in CAs carry fixed tags. It is display and filter only.
- Creating a custom CA and registering its account is one operation on the `UnitOfWork`: if the CA refuses registration, nothing is saved.
- Name, contact email and tag are editable on a custom CA. The directory URL and External Account Binding are fixed; changing them means deleting and recreating the CA. Deletion is refused while any Managed Certificate or Certificate refers to the CA, and otherwise removes its account and Secret.
- Directory URL validation: https only; loopback and link-local addresses (including the cloud metadata address) are refused; private ranges are allowed. The check runs when the CA is saved and again when the platform connects to it. The platform's egress rules are unchanged: reaching the CA is a deployment matter.
- DCV is DNS-01 only, through the existing DNS Providers and Validation Zones, with no per-CA DCV settings. ARI and revocation are used when the directory advertises them; if it advertises no revocation endpoint, revoking fails with a clear error.
- The `acmeAccount` permission resource gains `update` and `delete`, held only by Organization Administrators, as `create`, `read` and `test` are today. `/api/me` reports them, so the web checks permissions and not role names.
- Creating, editing and deleting a custom CA, and registering an account, each write an Audit Event through the `UnitOfWork`.
- The web app: the ACME accounts page lists every ACME CA with its tag, the registration dialog offers the built-ins (read-only configuration, contact email and terms only) and creating a custom CA, and the issuer picker for a Managed Certificate lists every ACME CA, then the Issuing CAs. A CA with no account stays visible and disabled with the existing "no account yet" error. Let's Encrypt Staging is the default.
- The in-app guides and `docs/` are updated.

## Testing Decisions

- A good test checks external behavior only: API responses, Audit Events, what an issuance produces, and that no API returns a Secret. It does not check how the code is arranged.
- One main seam: the HTTP API through the existing server test harness, against Pebble as the CA with the real ACME client, as `acme-accounts.test.ts` does. The built-in CAs resolve to Pebble in tests; a custom CA points at the same Pebble directory, or a second one if the harness can run two. This covers create, register, issue, renew, revoke, delete refused while referenced, URL refusal, permissions and Audit Events.
- The migration is tested the way `issuing-ca-migration.test.ts` tests the Issuing CA migration.
- The web seam is the existing web tests, only where there is real logic: disabled with no account, and the tag filter. No browser tests.
- Open risk: External Account Binding needs Pebble started with EAB required; whether the harness can do that is unconfirmed. Ticket 04 starts by checking it.
- Prior art: `acme-accounts.test.ts`, `issuance-attempts.test.ts`, `renewal.test.ts`, `issuing-ca-migration.test.ts`, `setup-guides-web.test.ts`.

## Out of Scope

- A custom trust root for a directory's TLS certificate.
- Bringing an existing account key instead of letting the platform make one.
- Editing a custom CA's directory URL or External Account Binding in place.
- DCV methods other than DNS-01, and per-CA DCV settings.
- Tags other than `staging` and `production`.
- A compatibility alias for `environment` in the API.

## Further Notes

- Ticket 01 changes no behavior: it is the prefactor the rest build on, in the way `.scratch/private-ca` ticket 01 made the issuer a kind.
- ADR 0002 (the platform never holds private keys it does not need to) and the write-only Secret rule apply to the EAB HMAC key.
