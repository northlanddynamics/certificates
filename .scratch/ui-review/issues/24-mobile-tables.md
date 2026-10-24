# 24: Tables scroll sideways on phones

**What to build:** At 390px every data table scrolls horizontally, cutting off the empty-state text ("No Managed Certificate…") and most columns. Below ~640px, show rows as stacked cards or keep only the key columns.

**Blocked by:** none

**Status:** needs-triage

- [ ] Decide: card layout in `components/data-table/data-table.tsx` driven by column meta (primary, secondary, hidden on mobile), or per-page column hiding.
- [ ] The empty state is centred in the visible width, not the table's.
- [ ] Pagination collapses to Previous / Page N of M / Next.
