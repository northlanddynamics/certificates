# 12: "Renew now" is the main action on a fresh certificate

**What to build:** A Managed Certificate issued minutes ago shows Renew now as the filled primary button. Renewing is rarely what you want then; downloading is. Let the primary action follow the state.

**Blocked by:** none

**Status:** needs-triage

- [ ] Decide the rule. Proposal: Download is primary while healthy; Renew now becomes primary when the latest Issuance failed or the certificate is inside its renewal window; otherwise Renew now moves to the ⋯ menu.
- [ ] Renew now asks for confirmation when the certificate is far from its renewal window.
