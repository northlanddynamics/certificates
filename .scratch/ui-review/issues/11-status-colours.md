# 11: Every status badge is the same black

**What to build:** Issued, Current, Active, Production and failure states all render as the same black badge, so nothing stands out. Give statuses semantic colours from theme tokens.

**Blocked by:** 02

**Status:** needs-triage

- [ ] Decide the palette: success (issued, current, active), warning (expiring within the renewal window, pending approval), danger (failed, revoked, expired), neutral (superseded, archived).
- [ ] Add success and warning tokens to `index.css` for light and dark, and Badge variants for them (via the shadcn CLI if a component is added).
- [ ] "Valid until" in the list and the Lifecycle card take the warning or danger colour near and after expiry.
- [ ] Environment tags (Staging, Production) use a separate style from statuses.

## Comments

Suggested palette, as soft tinted badges (tinted ground, coloured text), so that no status is solid black:
- success (emerald): Issued, Active, Current
- warning (amber): inside the renewal window, Awaiting Approval, Renewing…, Agent offline
- danger (the existing destructive): Issuance failed, Renewal failing or blocked, Revoked, Expired, Rejected, Agent revoked
- neutral (muted outline): Not issued, Superseded, Archived

`--success` and `--warning` tokens (light and dark) in `index.css` and `success`/`warning` Badge variants. Environment tags become outline badges with a dot (Production a filled dot, Staging a hollow one), so they never read as a status. Valid until and the Lifecycle card take warning inside the window and danger after expiry. Waiting on a yes.
