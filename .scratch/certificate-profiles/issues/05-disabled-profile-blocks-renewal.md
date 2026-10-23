# 05: A disabled Certificate Profile stops Renewal

**What to build:** While a Certificate Profile is disabled, no Managed Certificate made from it renews. The scheduler marks a due one as "Renewal blocked" and tells its Subscribers once. "Renew now" is refused. Everything that does not issue keeps working.

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] When a Managed Certificate linked to a disabled profile is due, the scheduler begins no Issuance and records it as renewal-blocked.
- [ ] A new *Renewal blocked* notice is sent to its Subscribers once, not again on each scheduler pass while it stays blocked.
- [ ] "Renew now" is refused with 422, naming the disabled profile, for Owners and Organization Administrators alike.
- [ ] The Managed Certificate's state reports the block; the inventory and details pages show "Renewal blocked".
- [ ] Revocation, downloads, changes to Owners, Subscribers and the Renewal Policy, and Archive keep working.
- [ ] Enabling the profile unblocks its Managed Certificates, and a due one renews on the next scheduler pass.
- [ ] Reading a profile also reports how many live Managed Certificates are linked to it; the disable confirmation shows that they will stop renewing.
- [ ] Expiry notices continue as usual.
- [ ] Scheduler tests driven like the existing renewal tests, server tests for "Renew now", and notification tests for the notice.
