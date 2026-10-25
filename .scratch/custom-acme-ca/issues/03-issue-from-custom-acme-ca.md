# 03: Issue Managed Certificates from a custom ACME CA

**What to build:** Someone creating a Managed Certificate picks between every ACME CA and Issuing CA in one picker, and a Certificate is issued, renewed and revoked through a custom ACME CA the way it is through Let's Encrypt.

**Blocked by:** 02

**Status:** done

- [x] The picker lists every ACME CA of the Organization with its tag badge, then the Issuing CAs; Let's Encrypt Staging stays the default; the list can be filtered by tag.
- [x] A CA with no account for the Organization is shown disabled with the existing "no account yet" error.
- [x] A Certificate is issued from a custom CA through DNS-01 with the existing DNS Providers and Validation Zones.
- [x] Renewal runs as for Let's Encrypt; the schedule follows the CA's ARI when the directory advertises it and is otherwise unchanged.
- [x] Revocation uses the CA's endpoint when advertised; when it is not, revoking fails with a clear error and nothing is recorded as revoked.
- [x] Server tests through the harness cover issue, renew and revoke against a custom CA; a web test covers the disabled state and the tag filter.

## Comments

- Issuance, Renewal, ARI and Revocation already went through the ACME CA by id (ticket 01), so a custom CA issues like a built-in one. Two changes: a Certificate from a custom CA records the CA's name as its `ca` (not `lets-encrypt`), and revoking at a CA whose directory lists no `revokeCert` is refused with 422 ("<CA> offers no revocation ...") before the CA is asked, with nothing recorded.
- `GET /acme-cas` gains `hasAccount`, to everyone in the Organization, so the picker can show a CA with no account disabled to a Member too; it no longer reads `/acme-accounts`. The picker's tag filter (every tag, Staging, Production, Untagged) narrows the ACME CAs only; Issuing CAs have no tag and stay listed. The logic is `web/src/lib/acme-ca-choices.ts`, tested in `server/test/acme-ca-picker-web.test.ts`.
- The harness serves Pebble's directory with chosen entries left out (`pebbleDirectoryWithout`, `server/test/support/directory-proxy.ts`), over TLS from a root of its own that the ACME client trusts beside Pebble's (`trustedCa` is now a list), for a CA with no revocation or no ARI. Scenarios: `server/test/custom-acme-ca-issuance.test.ts`.

