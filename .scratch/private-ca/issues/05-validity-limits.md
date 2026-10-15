# 05: Validity limits

**What to build:** Each Private CA sets a maximum and a default TLS validity (default 397 days), a Managed Certificate on a Private CA may choose a validity at or below the maximum, and nothing is issued that outlives its Issuing CA. See `spec.md`, "Validity".

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Organization Administrators set a Private CA's maximum and default validity in days; a default above the maximum is refused.
- [ ] A Managed Certificate on a Private CA may set its own validity; above the CA's maximum is refused, and without one it gets the default.
- [ ] Issued validity is the chosen validity, clipped to the Issuing CA's `notAfter`.
- [ ] The Renewal Policy's rules apply unchanged to these lifetimes.
- [ ] Web: the CA's limits on the Private CA page; a validity field on the Managed Certificate form when its issuer is a Private CA.
