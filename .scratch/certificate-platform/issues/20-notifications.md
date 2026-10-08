# 20: Notifications

**What to build:** Owners and Organization Administrators can add Subscribers (users, Teams or notification channels) to a Managed Certificate. Subscribers receive notices by email or webhook for upcoming expiry, Renewal succeeded, Renewal failed, Deployment Run failed, Agent offline and Approval decided. There are no default Subscribers, and being a Subscriber grants no visibility in the portal.

**Blocked by:** 07 (Owners and visibility), 09 (Renewal Policy and scheduler), 18 (First Deployment (tracer))

**Status:** ready-for-agent

- [ ] Owners and Organization Administrators can add and remove Subscribers; nobody is subscribed by default.
- [ ] Organization Administrators can configure email and webhook notification channels.
- [ ] Each listed event produces a notice to the Managed Certificate's Subscribers (captured in Seam A tests).
- [ ] A Subscriber who isn't an Owner receives notices but cannot see the Managed Certificate in the portal.
- [ ] Removing a user from the Organization removes them as a Subscriber.
- [ ] Subscriber and channel changes are audited.
