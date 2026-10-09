# 04: RFC 2136 DNS Provider

**What to build:** An Organization Administrator can connect an RFC 2136 DNS Provider (dynamic DNS updates authenticated with a TSIG key) and test the connection. This ticket defines the DNS Provider interface (present a TXT record, clean it up, test the connection) that every later provider implements.

**Blocked by:** 03 (Secrets and the Let's Encrypt ACME account)

**Status:** done

- [x] An Organization Administrator can add an RFC 2136 DNS Provider with server, zone and TSIG key; the TSIG key is stored as a write-only secret.
- [x] "Test connection" creates and removes a test TXT record and reports success or a meaningful error.
- [x] The DNS Provider interface is defined so that Infoblox and relayed execution can be added without changing callers.
- [x] Adding, changing and testing a DNS Provider is audited.

## Comments

Implemented on `main`; typecheck and the full Seam A suite pass against Postgres, Pebble and BIND in Docker Compose (`docker compose up -d --build --wait`).

- Routes: `GET`/`POST /api/organizations/{orgId}/dns-providers`, `PUT .../{providerId}` (name and settings), `PUT .../{providerId}/secret`, `POST .../{providerId}/test`; permission `dnsProvider` (Organization Administrator only). A provider is `{ name, type: "rfc2136", settings: { server, port (53), zone, keyName, algorithm (hmac-sha256) }, secret }`; the secret is the TSIG key's base64 secret and is returned by nothing. Names are unique within an Organization. There is no delete yet: nothing can use a provider until ticket 05.
- The interface is `DnsProvider` in `server/src/dns-provider.ts` (`presentTxt`, `cleanUpTxt`, `testConnection`). A provider is built from plain data (kind, settings, secret) by an entry in `server/src/dns-provider-kinds.ts`, so Infoblox (14) is a module and an entry, and relayed execution (16) can hand the same data to an Agent; callers get one from `DnsProviders.open(db, orgId, providerId)` and never see the secret.
- `cleanUpTxt` deletes only the one record (RFC 2136 class NONE), so a name shared by two challenges keeps the other; it and `presentTxt` are idempotent.
- "Test connection" publishes a throwaway TXT at `_acme-challenge.<zone>` (a name any update policy that lets the key do its job must allow) and removes it; if the removal fails the error names the record to delete by hand. It is always a 200 with `ok`, and every test, passing or failing, is audited (`dns_provider.tested`).
- The protocol is spoken directly (DNS UPDATE and TSIG, hmac-sha1/256/384/512 and md5) over TCP, and every reply must be correctly signed or the update counts as failed. Tests run against a real BIND (`docker/bind`), whose keys cover each algorithm. Not supported: GSS-TSIG (Windows secure dynamic updates) and UDP.
- Known: the platform connects to whatever `server` and `port` an administrator enters, and "test connection" tells them whether it answered. For a hosted platform that makes an Organization Administrator able to probe the platform's own network. Not addressed here; relayed providers (16) move internal DNS behind an Agent, and egress restrictions belong with deployment (26).
- CI (`.github/workflows/ci.yml`) now starts Pebble and BIND from `docker-compose.yml` before the tests (Postgres stays its service container). Not yet seen running on GitHub.

Review: stored settings or a secret that can no longer be used are now a failed, audited test rather than a 500, and any TSIG error code a server returns is reported. Left as they are, for the tickets that need them:

- Windows secure dynamic updates use GSS-TSIG, which is not built, so story 40 is met for BIND and any server that takes TSIG-signed updates but not for Windows DNS with secure updates.
- The interface has no "which names does this provider cover" accessor; 05 and 13 will need one (the settings carry a `zone` today, as plain data).
- "The same provider code" on an Agent (16) means a Go port of the DNS UPDATE and TSIG code; what the two share is the data shape (kind, settings, secret) and the BIND-backed tests as the behaviour to match. `DnsProviderError.kind` will need a value for "no relay Agent online".
- The connection test uses `_acme-challenge.<zone>`: a server whose policy allows only specific names, or where that name is a CNAME, fails the test although real challenges might work. If the update was applied but its reply lost, a test record can stay behind.
