# 07: Requests pending at ADCS

**What to build:** Templates that need CA manager approval work:
- `adcs.submit` may come back pending with an ADCS request ID. The Issuance stays pending and shows "pending at ADCS".
- The platform asks an Agent to re-check with `adcs.check` on a backoff, at most every 15 minutes, until the request is issued or denied, or until 7 days after it was submitted.
- A denial fails the Issuance with ADCS's disposition message, and the 7 days running out fails it as "pending too long".

See `.scratch/adcs/spec.md` (Pending and timeouts).

**Blocked by:** 06 (TLS Managed Certificates from an ADCS CA).

**Status:** ready-for-agent

- [ ] `adcs.submit` and `adcs.check` report `pending` with the request ID, and `adcs.check` is in the agent contract.
- [ ] A pending Issuance is re-checked on the backoff, through any online assigned Agent, and completes when ADCS issues.
- [ ] A denial and the 7-day timeout are distinct failure causes, shown in the UI.
- [ ] `adcsCa.requestPending` and `adcsCa.requestDenied` Audit Events.
- [ ] The template table and the issuer picker say which templates need CA manager approval.
- [ ] Seam A tests use the ADCS double's pending and deny switches. Go: the contract test covers check, pending and denied, and Seam B covers `adcs.check`.
