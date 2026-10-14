# 21: Audit search and SIEM forwarding

**What to build:** Organization Administrators can search and filter their Organization's audit log in the UI and stream it to a SIEM (such as CrowdStrike NG-SIEM) by webhook or syslog, using a stable, documented JSON event schema. Audit records are retained indefinitely.

**Blocked by:** 02 (Members, roles and Teams)

**Status:** done

- [x] The audit log can be searched and filtered by actor, action, target and time range.
- [x] Audit events follow a stable, versioned JSON schema that is documented.
- [x] Organization Administrators can configure webhook and syslog forwarding; events are delivered with retry and at-least-once semantics.
- [x] There is no retention limit and no API to delete audit records.
- [x] Forwarding configuration changes are audited.

## Comments

- Implemented. `GET /api/organizations/{orgId}/audit-events` filters by `actor` (a user's id or email), `action` (exact, or `team.*` for a resource), `targetType`, `targetId`, `from` and `to`, oldest or newest first (`order`), and pages by `cursor`. Leaving out every parameter still lists the whole log oldest first, up to 500 events. The web app has Audit log and Audit forwarding under Administration.
- Forwarders (`/api/organizations/{orgId}/audit-forwarders`) are a webhook, whose URL and optional Authorization header are a Secret, or syslog over TLS (RFC 5425 framing, RFC 5424 messages whose MSG is the JSON). Each Audit Event is queued for every forwarder in the transaction that records it (`audit_delivery`), so none is missed however transactions interleave. A pass every 30 seconds sends each forwarder its queue in id order. Ids are taken when an event is recorded, not when it commits, so two changes committing at the same moment can arrive the other way round; the doc says to order by `id`. On failure it waits 1, 5 and 30 minutes, then every hour, and never gives up. The schema is `certificate-platform.audit/1`, documented in `docs/audit-events.md`; a test checks that the doc lists every action.
- Not done here: as with webhook notification channels, a host name that resolves to an internal address is not refused; only names and IP literals written as such are. A syslog receiver must speak TLS; plain TCP and UDP syslog are not offered.

