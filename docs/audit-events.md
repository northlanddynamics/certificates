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
| `managed_certificate` | `created`, `proposed`, `approved`, `rejected`, `owner_added`, `owner_removed`, `subscriber_added`, `subscriber_removed`, `renewal_policy_changed`, `csr_uploaded`, `names_changed`, `archived`, `issuer_changed` |
| `certificate` | `revoked` |
| `private_ca` | `created`, `issuing_ca_added`, `csr_signed`, `updated`, `retired`, `revoked`, `crl_published` |
| `enrollment_profile` | `created` |
| `enrollment_validator` | `tested` |
| `enrollment` | `refused` |
| `device_certificate` | `issued`, `revoked` |
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

### Private CAs

`private_ca.created` targets the Private CA (`private_ca`, its id). Its `detail` has the `name`, `kind` (`platform_root` or `organization_root`), `keyAlgorithm`, its first Issuing CA's `subject`, the Issuing CA's `permittedNames` (`{ "exact": [...], "zones": [...] }`) and its `validity` (`{ "maximumDays": ..., "defaultDays": ... }`), and the Issuing CA's `id` in `issuingCa`. With a platform-made root it also has the `notAfter`, and the `serial` and SHA-256 `fingerprint` of the `root` and the `issuingCa` certificates; under the Organization's own root there are no certificates yet, and the Issuing CA awaits its signature. No key material is in it: the keys never leave the KMS.

`private_ca.issuing_ca_added` targets the Private CA too, when an Organization Administrator adds an Issuing CA under its root. Its `detail` has the Private CA's `name`, and in `issuingCa` the new Issuing CA's `id`, `subject`, `notAfter`, `permittedNames`, `validity`, and its certificate's `serial` and SHA-256 `fingerprint`. Under the Organization's own root it has no certificate yet: `issuingCa` has its `id`, `subject`, `status` (`awaiting_signature`), `permittedNames` and `validity`.

`private_ca.csr_signed` targets the Private CA too, when an Organization Administrator uploads the certificate the Organization's own root signed for one of its Issuing CAs and it is accepted, making the Issuing CA active. Its `detail` has the Private CA's `name`, and in `issuingCa` the Issuing CA's `id`, `subject`, `notAfter`, and its certificate's `serial` and SHA-256 `fingerprint`. With the first Issuing CA of the Private CA to be signed, which uploads the root and the chain above its Issuing CAs, it also has the `root` (`subject`, `serial`, `fingerprint`) and the `chain` (each certificate's, the one that signs the Issuing CAs first). A refused upload is not an event.

`private_ca.updated` targets the Private CA too, when an Organization Administrator changes one of its Issuing CAs. Its `detail` has the Private CA's `name`, the Issuing CA in `issuingCa` (`{ "id": ..., "subject": ... }`), and for each thing changed, what it was and what it is: `permittedNames: { "from": ..., "to": ... }`, and in `validity`, each of `maximumDays` and `defaultDays` changed, as `{ "from": ..., "to": ... }`. Changing both in one request is one event. A change that leaves everything as it was is not an event.

`private_ca.retired` targets the Private CA too, when an Organization Administrator retires one of its Issuing CAs: it issues nothing more, and keeps publishing its CRL until its last Certificate expires. Its `detail` has the Private CA's `name` and the Issuing CA in `issuingCa` (`{ "id": ..., "subject": ... }`).

`private_ca.revoked` targets the Private CA too, when an Organization Administrator revokes one of its platform-made Issuing CAs, which its root's CRL then lists. Its `detail` has the Private CA's `name`, in `issuingCa` the Issuing CA's `id`, `subject`, and its certificate's `serial` and SHA-256 `fingerprint`, and the RFC 5280 `reason` (`unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded` or `cessationOfOperation`).

`private_ca.crl_published` targets the Private CA when one of its CRLs is published again after its scheduled reissue had failed (the KMS did not sign it): by the platform (no actor) on a later pass, or with a change that publishes it, such as a revocation. A routine reissue is no event. Its `detail` has which `crl` (`issuing`, an Issuing CA's, with its `issuingCaId`, or `root`, the platform-made root's), its CRL `number`, and `failingSince`, when the reissue first failed.

A Managed Certificate issued from a Private CA is audited with the same actions as one from an ACME CA. Its `managed_certificate.created` (also when a Deployment creates it) or `managed_certificate.proposed`, `issuance.started`, `issuance.succeeded` and `issuance.failed` (once the Managed Certificate was read) have `detail.issuer`, `{ "kind": "private_ca", "issuingCaId": "..." }`, the Issuing CA it is issued from, and no `environment`. Its `managed_certificate.created` or `managed_certificate.proposed` also has `validityDays` when it chose a validity, and none when it gets the Issuing CA's default. A name change that gives it another validity says so in its `managed_certificate.names_changed`, `name_change.proposed` and `name_change.approved`, as `validityDays: { "from": ..., "to": ... }` (null for the Issuing CA's default); one that keeps its validity has no `validityDays`. Its `certificate.revoked` has `detail.issuer` too, and its `reason` may also be `affiliationChanged` or `privilegeWithdrawn`.

`managed_certificate.issuer_changed` targets the Managed Certificate when an Organization Administrator repoints it from one Issuing CA to another, as in rolling an Issuing CA over. Its `detail` has its `names`, and `from` and `to`, each `{ "kind": "private_ca", "issuingCaId": "..." }`. Repointing it to the Issuing CA it is on already is not an event.

### Device enrollment

`enrollment_profile.created` targets the Enrollment Profile (`enrollment_profile`, its id) an Organization Administrator created. Its `detail` has the `name`, the `issuingCa` it issues from (`id`, `subject`), `validityDays`, `keyUsage` and `extendedKeyUsage` (by name, such as `digitalSignature` and `clientAuth`), `allowedKeyTypes` (such as `rsa-2048`), the `validator` (`{ "kind": ..., "settings": { ... } }`, its kind's non-secret settings), its `nameRules` (null when its validator vouches for names), and the `serial` and `notAfter` of its `raCertificate`. Neither the RA's key nor the validator's secret is ever in it.

`device_certificate.issued` targets the Device Certificate (`device_certificate`, its id) a device enrolled for under an Enrollment Profile, with no actor (both null): a device is not a user. Its `detail` has the `enrollmentProfile` (`id`, `name`), the certificate's `serial` (upper-case hex), `subject` and `subjectAltNames` (each `{ "type": ..., "value": ... }`, the type being `dns`, `email`, `ip`, `url`, `upn` or `guid`), the `deviceId` its Enrollment Validator knows the device by (such as Intune's device ID; null when the request did not say), its `notAfter`, and the SCEP `transactionId` of the request.

`enrollment.refused` targets the Enrollment Profile (`enrollment_profile`, its id) under which a device's request was refused, with no actor. Its `detail` has the `enrollmentProfile` (`id`, `name`), the `reason` the device was given (such as a key the profile does not allow, a name its name rules do not, or the Enrollment Validator's own refusal), the `validator` (`{ "kind": ... }`), and the SCEP `transactionId`. Nothing is issued.

`enrollment_validator.tested` targets the Enrollment Profile whose Enrollment Validator an Organization Administrator tested. Its `detail` has the `validator` (`{ "kind": ... }`), `ok`, and the `error` when it failed.

`device_certificate.revoked` targets the Device Certificate revoked. When an Organization Administrator revoked it, they are the actor and there is no `detail.by`; when its Enrollment Validator's revocation feed asked for it, there is no actor, and `detail.by` is `{ "enrollmentValidator": { "kind": ... } }`. Its `detail` also has the `enrollmentProfile` (`id`, `name`), the `serial`, `subject`, and the RFC 5280 `reason` (such as `cessationOfOperation`). Its Issuing CA's CRL is reissued in the same change.
