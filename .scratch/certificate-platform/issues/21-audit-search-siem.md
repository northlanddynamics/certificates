# 21: Audit search and SIEM forwarding

**What to build:** Organization Administrators can search and filter their Organization's audit log in the UI and stream it to a SIEM (such as CrowdStrike NG-SIEM) by webhook or syslog, using a stable, documented JSON event schema. Audit records are retained indefinitely.

**Blocked by:** 02 (Members, roles and Teams)

**Status:** ready-for-agent

- [ ] The audit log can be searched and filtered by actor, action, target and time range.
- [ ] Audit events follow a stable, versioned JSON schema that is documented.
- [ ] Organization Administrators can configure webhook and syslog forwarding; events are delivered with retry and at-least-once semantics.
- [ ] There is no retention limit and no API to delete audit records.
- [ ] Forwarding configuration changes are audited.
