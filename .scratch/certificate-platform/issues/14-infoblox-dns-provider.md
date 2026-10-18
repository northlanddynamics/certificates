# 14: Infoblox DNS Provider

**What to build:** An Organization Administrator can connect an Infoblox DNS Provider (WAPI) and test the connection, using the DNS Provider interface from ticket 04.

**Blocked by:** 04 (RFC 2136 DNS Provider)

**Status:** done

- [x] An Organization Administrator can add an Infoblox DNS Provider with WAPI URL, credentials (write-only) and zone/view settings.
- [x] Present, clean up and test-connection work against Infoblox (verified with a WAPI test double at the provider boundary).
- [x] Infoblox can be used for Direct DCV and to host a Validation Zone.

## Comments

Implemented on `main`. Infoblox is a module and an entry (`server/src/issuance/dcv/infoblox.ts`, `dns-provider-kinds.ts`); the routes, permissions, audit and `DnsProviders.open` are the ones from ticket 04, unchanged.

- A provider is `{ name, type: "infoblox", settings: { url, zone, view ("default"), caCertificate? }, secret }`. `url` is the WAPI's including its version (`https://gm.example.com/wapi/v2.12`); https only, no embedded credentials. The secret is the WAPI user's credentials written `user:password` (HTTP Basic), write-only like every Secret. `caCertificate` (PEM) is for a grid whose certificate is not publicly trusted: certificates are always verified, never skipped; without it the system's roots are used.
- Present searches `record:txt` by name, text and view first and creates only when absent (TTL 60); clean up deletes exactly the matching record(s), so a name shared by two challenges keeps the other. Both are idempotent. Redirects are not followed (the credentials go with each request), and a reference to delete is followed only if it is a `record:txt` one. 401 is reported as refused credentials, other WAPI errors with the WAPI's own text, an unanswered or untrusted connection as "unreachable".
- "Test connection" is the one RFC 2136 uses (a throwaway TXT at `_acme-challenge.<zone>`, removed again), now shared as `testByThrowawayRecord` in `dns-provider.ts` along with `nameInZone`.
- Tests: `server/test/infoblox.test.ts` (the provider against `test/infoblox-double.ts`, an HTTPS WAPI double that checks the credentials, views and zones and answers as NIOS does) and `server/test/infoblox-dns-provider.test.ts` (the API, and real Issuances against Pebble for Direct DCV and for a Validation Zone, the double publishing to BIND where the CA looks). The double is not a real grid: WAPI behaviour beyond what it models (versions, session auth, permissions on zones) is untested.
- Not built: a grid reached only through an Agent (relayed execution, 16), WAPI session cookies, and DNS views other than the one configured per provider.

Security review of the commit: WAPI answers are now read to at most 1 MB and refused beyond it (resource exhaustion). Left as they are, and the same as ticket 04's known item: the platform connects to, and sends the WAPI credentials to, whatever https URL an Organization Administrator enters, so on a hosted platform an administrator can aim it at the platform's own network (SSRF) or at a host of their choosing (their own credentials, so nothing of anyone else's is exposed). Redirects are not followed and certificates are always verified. Restricting destinations is an egress/deployment control (26), or a relayed Agent (16), not something the provider can judge from a URL.
