# 03: Name rules on a Certificate Profile

**What to build:** An Organization Administrator gives a Certificate Profile name rules: exact names and zones, a maximum number of names, and whether wildcards are allowed. A non-administrator's Proposal through the profile, and their Name Change on a Managed Certificate made from it, must keep to the rules as they are now.

**Blocked by:** 02

**Status:** done

- [x] A profile may carry exact names and zones (a zone being a name and everything beneath it), a maximum number of names, and a wildcard on/off switch. With none, any names the issuer takes are allowed.
- [x] A non-administrator's Proposal with names outside the rules is refused with 422, naming the offending names.
- [x] A non-administrator's Name Change on a Managed Certificate linked to the profile is checked against the profile's current rules, the same way.
- [x] An Organization Administrator is held only to the issuer's limits, for both requests and Name Changes.
- [x] The issuer's limits (an Issuing CA's Permitted Name Rules, ACME DCV) still apply after the profile's rules.
- [x] Editing a profile's rules does not re-check pending Proposals.
- [x] The admin page edits the rules; the profile step and the names field show them.
- [x] Server tests through the harness, and a web test that the rules are shown.
