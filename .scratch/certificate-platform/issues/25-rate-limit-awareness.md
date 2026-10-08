# 25: Rate-limit awareness

**What to build:** The platform warns before actions likely to exceed Let's Encrypt rate limits and reports rate-limit failures clearly, so Organizations don't lock themselves out by accident.

**Blocked by:** 09 (Renewal Policy and scheduler)

**Status:** ready-for-agent

- [ ] Creating, renewing or re-keying a Managed Certificate warns when it would likely exceed Let's Encrypt limits for the Organization's ACME account.
- [ ] Rate-limit errors from the CA are surfaced with the limit hit and when it resets.
- [ ] ARI-coordinated Renewals are not warned about as if they counted against limits they are exempt from.
