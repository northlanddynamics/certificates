# 05: Keeping templates current

**What to build:** An ADCS CA's Certificate Templates follow ADCS:
- Discovery runs on Refresh and once a day, and refreshes the CA's chain each time.
- A template that is no longer published, no longer enrollable by the gMSA, or no longer reported shows as unavailable. It becomes available again when it comes back.
- Only templates that are published, enrollable and "Supply in the request" are offered. They're sorted for TLS (Server Authentication) or devices (Client Authentication), and a template with both is offered for both.
- An Organization Administrator can hide or show a template.

See `.scratch/adcs/spec.md` (ADCS CA module).

**Blocked by:** 04 (Tracer: add an ADCS CA and see its templates).

**Status:** ready-for-agent

- [ ] A Refresh button and a daily scheduled discovery for every ADCS CA. A failed discovery is recorded and shown, and leaves the stored templates as they were.
- [ ] A renewed ADCS CA certificate is picked up on the next discovery.
- [ ] Templates that disappear are kept and marked unavailable, and are available again when they come back.
- [ ] Templates built from Active Directory are listed as not usable, with the reason.
- [ ] The platform's API offers the available, unhidden templates for TLS and for devices separately, sorted by EKU.
- [ ] Hide and show, with `adcsCa.templateHidden` and `adcsCa.templateShown` Audit Events.
- [ ] `adcsCa.discovered` names the templates whose availability changed.
- [ ] Seam A tests drive each of these through the ADCS double.
