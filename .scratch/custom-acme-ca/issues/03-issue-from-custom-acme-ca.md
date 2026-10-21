# 03: Issue Managed Certificates from a custom ACME CA

**What to build:** Someone creating a Managed Certificate picks between every ACME CA and Issuing CA in one picker, and a Certificate is issued, renewed and revoked through a custom ACME CA the way it is through Let's Encrypt.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] The picker lists every ACME CA of the Organization with its tag badge, then the Issuing CAs; Let's Encrypt Staging stays the default; the list can be filtered by tag.
- [ ] A CA with no account for the Organization is shown disabled with the existing "no account yet" error.
- [ ] A Certificate is issued from a custom CA through DNS-01 with the existing DNS Providers and Validation Zones.
- [ ] Renewal runs as for Let's Encrypt; the schedule follows the CA's ARI when the directory advertises it and is otherwise unchanged.
- [ ] Revocation uses the CA's endpoint when advertised; when it is not, revoking fails with a clear error and nothing is recorded as revoked.
- [ ] Server tests through the harness cover issue, renew and revoke against a custom CA; a web test covers the disabled state and the tag filter.
