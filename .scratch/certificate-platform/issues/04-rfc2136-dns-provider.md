# 04: RFC 2136 DNS Provider

**What to build:** An Organization Administrator can connect an RFC 2136 DNS Provider (dynamic DNS updates authenticated with a TSIG key) and test the connection. This ticket defines the DNS Provider interface (present a TXT record, clean it up, test the connection) that every later provider implements.

**Blocked by:** 03 (Secrets and the Let's Encrypt ACME account)

**Status:** ready-for-agent

- [ ] An Organization Administrator can add an RFC 2136 DNS Provider with server, zone and TSIG key; the TSIG key is stored as a write-only secret.
- [ ] "Test connection" creates and removes a test TXT record and reports success or a meaningful error.
- [ ] The DNS Provider interface is defined so that Infoblox and relayed execution can be added without changing callers.
- [ ] Adding, changing and testing a DNS Provider is audited.
