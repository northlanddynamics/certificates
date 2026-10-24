# 05: Organization settings are only in the user menu

**What to build:** Sign-in settings, Notification channels and API keys are Organization pages, but only the user menu opens them (`organizationAccountNav` in `lib/navigation.ts`). Administrators look for them in the sidebar. Add a Settings group to the sidebar.

**Blocked by:** none

**Status:** needs-triage

- [ ] Decide: move them to a sidebar Settings group, or show them in both places.
- [ ] The group keeps today's permission checks (Sign-in settings while MFA setup is required stays reachable).
- [ ] The user menu keeps Account security, theme (ticket 02) and Sign out.
