# 13: Delegated DCV and Validation Zones

**What to build:** An Organization Administrator can define a Validation Zone on one of their DNS Providers and choose, per name or zone, whether DCV is Direct or Delegated and through which DNS Provider. For Delegated DCV the platform shows the exact `_acme-challenge` CNAME record to create, and writes challenge records into the Validation Zone.

**Blocked by:** 05 (First Certificate (tracer))

**Status:** ready-for-agent

- [ ] An Organization Administrator can define a Validation Zone on an Organization DNS Provider.
- [ ] DCV method (Direct or Delegated) and DNS Provider can be set per name or zone.
- [ ] The platform shows the CNAME record the Organization must create for each Delegated name.
- [ ] Issuance succeeds via Delegated DCV against Pebble with the challenge TXT written into the Validation Zone.
- [ ] There is no shared, platform-wide Validation Zone (ADR 0003); no cross-Organization detection is attempted.
- [ ] Configuration changes are audited.
