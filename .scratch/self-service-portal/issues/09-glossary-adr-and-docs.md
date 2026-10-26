# 09: Glossary, ADR and docs for the Self-Service Portal

**What to build:** The domain language, the decision record and the admin documentation for the Self-Service Portal, so that the next person understands the two front ends and how to set up the identity provider.

**Blocked by:** 02 (Who a connection admits), 03 (Sessions land in their front end)

**Status:** ready-for-agent

- [ ] `CONTEXT.md` defines **Self-Service Portal** and **Console**, and updates **SSO Connection**: one per email domain per front end, which front end it signs in to and whom it admits.
- [ ] A new ADR records that the Self-Service Portal is a second front end on the same platform, sharing one identity, one API and one set of roles. It records why the alternatives were not chosen: the platform as an IdP for a portal hosted elsewhere, a separate host, and roles from identity provider groups.
- [ ] Admin docs explain how to set up the two identity provider apps (assignments, SP values, start URLs) and the recommended admission for each.
