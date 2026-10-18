# 05: First Certificate (tracer)

**What to build:** An Organization Administrator creates a Managed Certificate with Owner Key Custody by entering names, a key algorithm and a CSR. The platform validates the CSR, places an ACME order, performs Direct DCV through the Organization's DNS Provider, finalizes with the CSR, stores the Certificate (identified by its SHA-256 fingerprint) and offers it for download as PEM. This proves the full path: UI → API → Issuance → DCV → DNS Provider → CA → stored Certificate.

**Blocked by:** 03 (Secrets and the Let's Encrypt ACME account), 04 (RFC 2136 DNS Provider)

**Status:** done

- [x] An Organization Administrator can create a Managed Certificate with names (wildcards allowed), a key algorithm (ECDSA P-256 or P-384; RSA 2048, 3072 or 4096) and a CSR; no Approval is needed.
- [x] A CSR is rejected if its key algorithm differs from the Managed Certificate's or its names don't exactly match the names being issued.
- [x] Issuance runs against Pebble with Direct DCV through the RFC 2136 DNS Provider, and the challenge TXT record is removed afterwards.
- [x] The issued Certificate is stored immutably with fingerprint, serial, validity dates, names, chain, and the CA and ACME account it came from.
- [x] The current Certificate can be downloaded as PEM (full chain).
- [x] DCV and issuance failures surface meaningful causes (DNS update rejected, record not visible, CA error).
- [x] Issuance happens behind a Certificate Authority interface with Let's Encrypt as the only implementation.
- [x] Creation and issuance are audited.

## Comments

Implemented on `main`; typecheck and the full Seam A suite pass against Postgres, Pebble and BIND in Docker Compose (`docker compose up -d --build --wait`). Pebble now checks DNS-01 against BIND (`-dnsserver bind:53`), so the tests run the real path: RFC 2136 update, visibility check, the CA reading the record back, removal.

- Routes: `GET`/`POST /api/organizations/{orgId}/managed-certificates`, `GET .../{id}`, `GET .../{id}/certificates`, `GET .../{id}/certificate.pem` (the current Certificate, leaf then the CA's intermediates), `POST .../{id}/issuances` (try again after a failure). New permission `managedCertificate` (`read`, `create`, `issue`), Organization Administrator only.
- Request: `{ names, keyAlgorithm: ecdsa-p256|ecdsa-p384|rsa-2048|rsa-3072|rsa-4096, csr, environment (default staging) }`. The CSR must be signed by its own key (proof the Owner holds it), be for that algorithm and ask for exactly the names (400 for what is not a CSR or name, 422 for a mismatch). The subject CN counts as a name, so a CSR whose CN is not also a SAN does not match.
- New term **Issuance** (CONTEXT.md): one attempt, recorded as `issuance` rows with `running | succeeded | failed` and, on failure, a code and the cause (`no_acme_account`, `no_dns_provider`, `dns_update_rejected`, `dns_provider_unreachable`, `record_not_visible`, `ca_rejected`, `ca_unreachable`, `interrupted`, `internal`). It runs in the background after the request commits; the Managed Certificate shows its latest Issuance and its current Certificate. Audited: `managed_certificate.created` (with the CSR's fingerprint), `issuance.started`, `issuance.succeeded`, `issuance.failed`, attributed to whoever asked.
- A Certificate is immutable (a trigger rejects UPDATE and DELETE), identified by its SHA-256 fingerprint, and keeps names, serial, validity, the chain, the CA (`lets-encrypt`) and the ACME account. What the CA issued is checked against the CSR (same key, same names) before it is stored.
- The CA interface gained `issue` (order, DCV through a `DnsChallengeResponder`, finalize); DCV is `server/src/issuance/dcv/dcv.ts` (Direct only; the DNS Provider for a name is the Organization's one with the most specific zone, via `DnsProviderKind.zoneOf`, the accessor ticket 04 asked for).
- Web: the home page lists Managed Certificates with their Issuance state (refreshing while one runs) and, for those who may, creates one and downloads the PEM.

Known, left for the tickets that need them:

- Issuance is an in-process background task, not yet on the Postgres job queue (09 will bring one). A restart ends running Issuances as `interrupted` (`failInterrupted` at start-up), which assumes one platform instance; with several, one starting would end the others' live runs, though a Certificate the CA did issue is still stored.
- A challenge record that cannot be removed does not fail the Issuance; it is listed in the `issuance.succeeded`/`issuance.failed` audit detail (`challengeRecordsNotRemoved`) but not in the API or UI.
- The visibility check looks the record up through the host's resolvers (`createTxtResolver`), which for a real zone can be slower than asking its authoritative servers; each lookup uses a fresh resolver because Bun's shared one answers from a cache.
- The list shows nothing to roles without `managedCertificate: read` (Approvers and Members) rather than 403; visibility for them (06, 07) is not built. Existing rows (none outside tests) would need the new NOT NULL columns of migration 0006.
- Without an ACME account in the chosen environment, or a DNS Provider for a name, creation succeeds and the Issuance fails with that cause.
