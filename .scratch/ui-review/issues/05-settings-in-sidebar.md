# 05: Organization settings are only in the user menu

**What to build:** Sign-in settings, Notification channels and API keys are Organization pages, but only the user menu opens them (`organizationAccountNav` in `lib/navigation.ts`). Administrators look for them in the sidebar. Add a Settings group to the sidebar.

**Blocked by:** none

**Status:** done

- [x] Decide: move them to a sidebar Settings group, or show them in both places.
- [x] The group keeps today's permission checks (Sign-in settings while MFA setup is required stays reachable).
- [x] The user menu keeps Account security, theme (ticket 02) and Sign out.

## Comments

Decided: move each to the sidebar group it belongs with, and out of the user menu. Sign-in settings joins Members and Teams under Organization; Notification channels joins ACME accounts and DNS Providers under Administration › Integrations; API keys, open to every member, sits under Automation. The user menu keeps Account security, Theme and Sign out.
