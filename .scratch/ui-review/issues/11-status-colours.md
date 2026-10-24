# 11: Every status badge is the same black

**What to build:** Issued, Current, Active, Production and failure states all render as the same black badge, so nothing stands out. Give statuses semantic colours from theme tokens.

**Blocked by:** 02

**Status:** needs-triage

- [ ] Decide the palette: success (issued, current, active), warning (expiring within the renewal window, pending approval), danger (failed, revoked, expired), neutral (superseded, archived).
- [ ] Add success and warning tokens to `index.css` for light and dark, and Badge variants for them (via the shadcn CLI if a component is added).
- [ ] "Valid until" in the list and the Lifecycle card take the warning or danger colour near and after expiry.
- [ ] Environment tags (Staging, Production) use a separate style from statuses.
