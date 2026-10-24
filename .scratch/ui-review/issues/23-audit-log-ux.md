# 23: Audit log shows raw ids and a large filter form

**What to build:** Targets show UUIDs ("organization 85a0e0ec-…"), and six filter fields are always open above the table.

**Blocked by:** none

**Status:** needs-triage

- [ ] Targets show the name when the event carries one and link to its page; the id stays in the expanded row with a copy button. Check whether the API returns names; if not, note the server work.
- [ ] Filters collapse to a search box (actor or action) plus chips for target type and a time range with quick picks (24h, 7d, 30d, custom).
- [ ] Filters live in the URL.

## Comments

Findings: an Audit Event's target is only `{ type, id }` (`audit.ts`); some details carry a name (names of a Managed Certificate, an owner's email, an invitation's email), most do not, so showing names needs the server to resolve them when listing (a lookup per target type, and a fallback for deleted ones) or to record a name at write time (new events only). Filters are six free-text fields searched on Search. Waiting on a decision on the server side and the filter design.
