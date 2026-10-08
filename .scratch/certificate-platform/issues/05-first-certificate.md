# 05: First Certificate (tracer)

**What to build:** An Organization Administrator creates a Managed Certificate with Owner Key Custody by entering names, a key algorithm and a CSR. The platform validates the CSR, places an ACME order, performs Direct DCV through the Organization's DNS Provider, finalizes with the CSR, stores the Certificate (identified by its SHA-256 fingerprint) and offers it for download as PEM. This proves the full path: UI → API → Issuance → DCV → DNS Provider → CA → stored Certificate.

**Blocked by:** 03 (Secrets and the Let's Encrypt ACME account), 04 (RFC 2136 DNS Provider)

**Status:** ready-for-agent

- [ ] An Organization Administrator can create a Managed Certificate with names (wildcards allowed), a key algorithm (ECDSA P-256 or P-384; RSA 2048, 3072 or 4096) and a CSR; no Approval is needed.
- [ ] A CSR is rejected if its key algorithm differs from the Managed Certificate's or its names don't exactly match the names being issued.
- [ ] Issuance runs against Pebble with Direct DCV through the RFC 2136 DNS Provider, and the challenge TXT record is removed afterwards.
- [ ] The issued Certificate is stored immutably with fingerprint, serial, validity dates, names, chain, and the CA and ACME account it came from.
- [ ] The current Certificate can be downloaded as PEM (full chain).
- [ ] DCV and issuance failures surface meaningful causes (DNS update rejected, record not visible, CA error).
- [ ] Issuance happens behind a Certificate Authority interface with Let's Encrypt as the only implementation.
- [ ] Creation and issuance are audited.
