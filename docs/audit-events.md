# Audit Event schema: `certificate-platform.audit/1`

Every Audit Event an Organization's audit forwarders send is one JSON object in this schema. The search API (`GET /api/organizations/{orgId}/audit-events`) returns the same objects without `schema` and `organization`.

The schema is stable. Within version 1, fields are only ever added: new top-level fields, new fields in `detail`, and new actions. A consumer must ignore what it does not know. Removing or renaming a field, or changing what one means, makes a new version (`certificate-platform.audit/2`), which a forwarder would have to be set up for.

```json
{
  "schema": "certificate-platform.audit/1",
  "id": "4182",
  "occurredAt": "2026-02-01T09:00:00.000Z",
  "organization": { "id": "b3f0c3a4..." },
  "actor": { "id": "Yd1m3...", "email": "admin@acme.test" },
  "action": "team.created",
  "target": { "type": "team", "id": "Tq9x..." },
  "detail": { "name": "Web" }
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Always `certificate-platform.audit/1` for this version. |
| `id` | string of digits | Unique across the platform, and greater for an event recorded later. Compare as numbers. Delivery is at least once, so deduplicate by `id`. |
| `occurredAt` | string | When the change happened, in ISO 8601 UTC with milliseconds. Events of one change have the same time. |
| `organization.id` | string | The Organization the event belongs to. |
| `actor.id`, `actor.email` | string or null | The user who made the change. Both are null when the platform made it, such as a scheduled Renewal, or when an Organization's API key did. An API key's use (`api_key.used`) names the key in `detail`. |
| `action` | string | What was done, as `<resource>.<verb>`. See below. |
| `target.type`, `target.id` | string, string or null | What it was done to, such as `managed_certificate` and its id. |
| `detail` | object | What the action records besides. Its fields depend on the action. It never holds a secret (a credential, a webhook's URL, a private key). |

## Delivery

- **Webhook:** one HTTP `POST` per event, with `Content-Type: application/json` and, if the forwarder has one, its `Authorization` header. Any 2xx answer counts as delivered. Anything else, a redirect included, or no answer within 10 seconds, is a failure.
- **Syslog:** over TLS (RFC 5425), each message framed by its length in octets. Each message is RFC 5424, with facility 13 (log audit) and severity 6 (informational), so `<110>`. The timestamp is the event's `occurredAt`, the host name is the platform's and the APP-NAME is `certificate-platform`. MSGID is `audit`, there is no structured data, and MSG is the event's JSON:

  ```
  <110>1 2026-02-01T09:00:00.000Z platform-1 certificate-platform - audit - {"schema":"certificate-platform.audit/1",...}
  ```

Events are sent in the order of their `id`. An id is taken when an event is recorded, not when its change commits, so of two changes committing at about the same moment, the event with the greater id may arrive first. Order by `id` or `occurredAt` where order matters. A forwarder that fails is tried again after 1, 5 and 30 minutes, then every hour until it succeeds. Nothing is ever given up, and an event may arrive more than once.

## Actions

Each resource's verbs, as of this writing. New ones may be added within version 1.

| Resource | Verbs |
| --- | --- |
| `organization` | `created` |
| `invitation` | `created`, `accepted`, `rejected`, `canceled` |
| `member` | `role_changed`, `removed`, `provisioned` |
| `team` | `created`, `renamed`, `deleted`, `member_added`, `member_removed` |
| `acme_account` | `created`, `key_replaced` |
| `dns_provider` | `created`, `changed`, `secret_replaced`, `tested`, `relay_changed` |
| `validation_zone` | `created`, `deleted` |
| `dcv_rule` | `created`, `changed`, `deleted` |
| `managed_certificate` | `created`, `proposed`, `approved`, `rejected`, `owner_added`, `owner_removed`, `subscriber_added`, `subscriber_removed`, `renewal_policy_changed`, `csr_uploaded`, `names_changed`, `archived` |
| `certificate` | `revoked` |
| `name_change` | `proposed`, `approved`, `rejected`, `withdrawn`, `discarded` |
| `issuance` | `started`, `succeeded`, `failed` |
| `api_key` | `created`, `revoked`, `used` |
| `agent_registration_token` | `created` |
| `agent` | `registered`, `credential_rotated`, `revoked` |
| `deployment_script` | `uploaded` |
| `deployment` | `created`, `key_generated`, `key_failed`, `key_requested`, `run_requested` |
| `deployment_run` | `succeeded`, `failed` |
| `notification_channel` | `created`, `deleted` |
| `audit_forwarder` | `created`, `deleted` |
| `two_factor` | `enabled`, `disabled`, `backup_codes_regenerated` |
| `passkey` | `registered`, `renamed`, `deleted` |
| `login_policy` | `changed` |
| `sso_connection` | `created`, `changed`, `deleted`, `domain_verified`, `tested` |
