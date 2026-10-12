# 13: Delegated DCV and Validation Zones

**What to build:** An Organization Administrator can define a Validation Zone on one of their DNS Providers and choose, per name or zone, whether DCV is Direct or Delegated and through which DNS Provider. For Delegated DCV the platform shows the exact `_acme-challenge` CNAME record to create, and writes challenge records into the Validation Zone.

**Blocked by:** 05 (First Certificate (tracer))

**Status:** done

- [x] An Organization Administrator can define a Validation Zone on an Organization DNS Provider.
- [x] DCV method (Direct or Delegated) and DNS Provider can be set per name or zone.
- [x] The platform shows the CNAME record the Organization must create for each Delegated name.
- [x] Issuance succeeds via Delegated DCV against Pebble with the challenge TXT written into the Validation Zone.
- [x] There is no shared, platform-wide Validation Zone (ADR 0003); no cross-Organization detection is attempted.
- [x] Configuration changes are audited.

## Comments

Implemented; typecheck and the full Seam A suite pass against Postgres, Pebble and BIND. Tests: `server/test/dcv-configuration.test.ts` (the API) and `server/test/delegated-dcv.test.ts` (Issuances against Pebble).

### What it does

- **Validation Zones** (`/api/organizations/{orgId}/validation-zones`: list, create, delete): a zone name on one of the Organization's DNS Providers, which must be inside the provider's own zone (`DnsProviderKind.zoneOf`). Removing one is refused (409) while a rule delegates through it. Not changeable: a rename would orphan the CNAMEs the Organization already made.
- **DCV Rules** (`/dcv-rules`: list, create, change, delete): per `name` (that name and its wildcard) or `zone` (the name and everything beneath it), Direct (optionally through a named DNS Provider) or Delegated (through a Validation Zone). The most specific rule decides: a name's own, then the longest zone. With no rule, DCV is Direct through whichever provider publishes the name, exactly as before.
- **The CNAME to create**: `GET /dcv/preview?name=` shows how DCV is done for a name (the deciding rule, the DNS Provider, the Validation Zone) and, for a Delegated one, the record: `_acme-challenge.<name>` CNAME `<name>.<Validation Zone>`. A wildcard shows its base name's record. The target is the name itself under the zone, so no two names meet in the Validation Zone, and a wildcard and its base share one record name (two values), as they do in Direct DCV.
- **Issuance**: `dcv-plan.ts` decides per name (the preview and DCV share it, so what is shown is what happens; it is decided once per Issuance, so what is cleaned up is what was published); `dcv.ts` writes the TXT at the target through the zone's provider, waits until `_acme-challenge.<name>`, where the CA looks, shows it, and removes it. Failures: `no_dns_provider` (now in terms of the rule or Validation Zone), `dns_update_rejected`, `dns_provider_unreachable`, `record_not_visible`, and the new `cname_missing`, which says which record to create or where the existing one points.
- Permissions `validationZone` and `dcvRule` (Organization Administrators only; the preview needs `dcvRule: read`). Audit Events `validation_zone.created/deleted`, `dcv_rule.created/changed/deleted`, written with the change. Everything is per Organization; there is no platform-wide zone and no cross-Organization detection (ADR 0003), with a test that another Organization's names are not delegated through this one's zone.
- Migration 0017 (`validation_zone`, `dcv_rule`; composite foreign keys keep both inside one Organization). `DnsProviders.findFor` became `locate` (no secret opened; optionally restricted to one provider), and `Dcv.directFor` became `responderFor`.

### Notes

- **Test DNS changed**: BIND now serves `delegating.test` (static CNAMEs into `validation.rfc2136.test`) and is recursive: a non-recursive BIND does not chain a CNAME into another of its zones, and Pebble (like the real CA) needs the answer to. After changing `docker/bind`, recreate the container with `docker compose up -d --build --force-recreate --renew-anon-volumes bind`, because the base image keeps its config as a volume.
- `createTxtResolver` follows a CNAME itself when a name has no TXT, because Node's resolver does not chase one. `TxtResolver` gained `lookupCname`.
- No web page: DNS Providers have none either, and the ticket is about the API; the preview endpoint is what a page would show.
- Left: a delegation target longer than 253 characters (a long name under a long zone) fails DCV with `dns_update_rejected` and says so; the CNAME is only checked when the TXT does not show up, so a missing CNAME costs the visibility timeout (two minutes) before it is reported.

### Review follow-ups

- The plan carries its `domain`, so DCV no longer strips wildcards itself; the glossary's "DCV Rule" casing is used throughout.
- Known, left: the CNAME is checked only after the visibility timeout, because a CNAME created a moment ago may not have propagated, and failing at once would turn that into a false failure; the TXT stays published meanwhile. A platform that stops between publishing and removing a record leaves it, and a retry plans from the rules as they then stand (the same as Direct DCV). Changing a DNS Provider's zone after a Validation Zone or rule was made on it is not re-checked; DCV then fails with `no_dns_provider` naming the zone or rule. `POST validation-zones` and rule changes check the provider and zone before their transaction; the composite foreign keys keep a racing change inside the Organization. The preview shows one name per call; a page listing a Managed Certificate's CNAMEs would call it for each name.
- One test in the first full run failed once and did not fail in the next two runs of the suite, so it was not identified; the full run after the review changes passed.
