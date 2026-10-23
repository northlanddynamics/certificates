# 08: Guides and docs for Certificate Profiles

**What to build:** Organization Administrators and requesters can read how Certificate Profiles work: setting one up, proposing through one, what disabling does to Renewal, and detaching as the way out.

**Blocked by:** 03, 06, 07

**Status:** done

- [x] An in-app guide on the Certificate Profiles page, in the style of the existing setup guides.
- [x] A `docs/` page on Certificate Profiles, using the glossary's terms and linking ADR 0012.
- [x] `docs/audit-events.md` lists the new Audit Events.
- [x] The OpenAPI descriptions of the profile routes and the create route state what is copied, what is checked live, and that disabling stops Renewal.
- [x] The glossary and ADR 0012 still match what was built; any difference is corrected.

## Comments

- The repo has no setup-guide component (see custom ACME CA ticket 06), so the in-app guide is a folded "How Certificate Profiles work" section on the Certificate Profiles page, using the Collapsible pattern of the CSR Generator and the details views. Its text is `web/src/lib/certificate-profile-guide.ts`, a short form of `docs/certificate-profiles.md` with the same sections; the docs page is linked from a new README section, and the README's Notifications section names the *Renewal blocked* notice.
- `docs/audit-events.md` already listed the profile Audit Events (written with tickets 01 to 07); `certificate-profile-guide.test.ts` holds the guide to that list, to the in-app guide's sections and to ADR 0012's link.
- OpenAPI: the profile create, edit and read routes, the `enabled` field, the create-Managed-Certificate route and its `profileId` now say what is copied, what is checked live and that disabling stops Renewal.
- Corrected against what was built: the glossary's Owner and Certificate Profile, and ADR 0012, said "proposes" where an Organization Administrator's request, created outright, also makes the requester an Owner and copies the settings; they now say "requests". The *Renewal blocked* notice now names detaching as a way out, as the details page's alert does.
