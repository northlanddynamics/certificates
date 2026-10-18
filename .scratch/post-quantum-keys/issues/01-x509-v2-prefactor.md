# 01: Move to @peculiar/x509 2.x

**What to build:** The server and the web app use `@peculiar/x509` 2.x, with no change in behaviour, so that ML-DSA CSRs, certificates and CRLs can be parsed and verified. See `spec.md`, "X.509 library".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Root and `web/` `package.json` pin the same 2.x version; `reflect-metadata` is imported before the library everywhere it loads (server entry, tests, web entry).
- [ ] The `@peculiar/asn1-schema` override in the root `package.json` is kept, changed or removed, with the reason in the commit message.
- [ ] `bun run typecheck` and `bun test server/test` pass; the web build passes.
