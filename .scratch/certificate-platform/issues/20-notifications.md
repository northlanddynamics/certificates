# 20: Notifications

**What to build:** Owners and Organization Administrators can add Subscribers (users, Teams or notification channels) to a Managed Certificate. Subscribers receive notices by email or webhook for upcoming expiry, Renewal succeeded, Renewal failed, Deployment Run failed, Agent offline and Approval decided. There are no default Subscribers, and being a Subscriber grants no visibility in the portal.

**Blocked by:** 07 (Owners and visibility), 09 (Renewal Policy and scheduler), 18 (First Deployment (tracer))

**Status:** done

- [x] Owners and Organization Administrators can add and remove Subscribers; nobody is subscribed by default.
- [x] Organization Administrators can configure email and webhook notification channels.
- [x] Each listed event produces a notice to the Managed Certificate's Subscribers (captured in Seam A tests).
- [x] A Subscriber who isn't an Owner receives notices but cannot see the Managed Certificate in the portal.
- [x] Removing a user from the Organization removes them as a Subscriber.
- [x] Subscriber and channel changes are audited.

## Comments

- Implemented. Notices are queued in Postgres with the change they tell of and sent by a once-a-minute pass (`notifications.tick()`), which also notices silent Agents and Certificates nearing their end (14, 7 and 1 days before; once each). Webhooks get JSON with `"schema": "certificate-platform.notice/1"`; a webhook URL is a Secret, must be https and cannot name localhost or an internal IP literal. A failed Deployment Run's notice carries the exit code but not the script output, since a Subscriber may not see the Deployment.
- Not done here: a real SMTP transport (the server still uses the console `Mailer`), and resolving webhook host names to refuse ones that point at internal addresses.
