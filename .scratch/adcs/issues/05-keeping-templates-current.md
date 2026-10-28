# 05: Keeping templates current

**What to build:** An ADCS CA's Certificate Templates follow ADCS:
- Discovery runs on Refresh and once a day, and refreshes the CA's chain each time.
- A template that is no longer published, no longer enrollable by the gMSA, or no longer reported shows as unavailable. It becomes available again when it comes back.
- Only templates that are published, enrollable and "Supply in the request" are offered. They're sorted for TLS (Server Authentication) or devices (Client Authentication), and a template with both is offered for both.
- An Organization Administrator can hide or show a template.

See `.scratch/adcs/spec.md` (ADCS CA module).

**Blocked by:** 04 (Tracer: add an ADCS CA and see its templates).

**Status:** done

- [x] A Refresh button and a daily scheduled discovery for every ADCS CA. A failed discovery is recorded and shown, and leaves the stored templates as they were.
- [x] A renewed ADCS CA certificate is picked up on the next discovery.
- [x] Templates that disappear are kept and marked unavailable, and are available again when they come back.
- [x] Templates built from Active Directory are listed as not usable, with the reason.
- [x] The platform's API offers the available, unhidden templates for TLS and for devices separately, sorted by EKU.
- [x] Hide and show, with `adcsCa.templateHidden` and `adcsCa.templateShown` Audit Events.
- [x] `adcsCa.discovered` names the templates whose availability changed.
- [x] Seam A tests drive each of these through the ADCS double.

## Comments

- Server: `server/src/adcs/adcs-ca.ts`. `POST /adcs-cas/{id}/refresh` (502 when no assigned Agent reaches the CA, 422 when it refuses), and `discoverDue()`, which `registerAdcsCas` now returns, run hourly from `index.ts`, discovers each CA whose last discovery (succeeded or failed) was a day ago or more (`h.runAdcsDiscovery()` in tests). Migration 0061: `adcs_ca.discovery_failed_at` and `discovery_error` (cleared by the next discovery that works), `adcs_template.reported` and `hidden`.
- A template keeps its id from one discovery to the next, matched by name case-insensitively, so later tickets can reference `adcs_template.id`. One no longer reported stays, `reported: false`.
- Availability, its reason, and what a template is offered for are in `adcs-kinds.ts` (`unavailableReason`, `purposesOf`, `offeredFor`), shared with the web. The API reports per template `reported`, `available`, `unavailableReason`, `hidden`, `offeredFor`, and per CA `offered: { tls, devices }` (template ids, by name) and `discoveryFailure`. The issuer pickers of tickets 06 and 10 should read `offered`.
- Audit actions: `adcs_ca.discovery_failed`, `adcs_ca.template_hidden`, `adcs_ca.template_shown`; `adcs_ca.discovered` now lists `templates.becameAvailable` and `becameUnavailable`, and its `available` and `unavailable` are by name.
- Hide and show are `POST /adcs-cas/{id}/templates/{templateId}/hide` and `/show`, 409 when already so.
