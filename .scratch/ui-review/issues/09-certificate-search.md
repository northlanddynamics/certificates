# 09: Managed Certificates list has no text search

**What to build:** The list filters only by facet (Status, Environment tag, Key algorithm, Key Custody). With many certificates, finding one by name means paging. Add a search box.

**Blocked by:** none

**Status:** done

- [x] A search input before the facet filters matches common name and every SAN, case-insensitively, as you type.
- [x] The query is kept in the URL search params so it survives Back and can be shared.
- [x] If the list is paged on the server, the search goes to the API; otherwise it filters client-side.
- [x] The empty state says no certificate matches, with Clear.
