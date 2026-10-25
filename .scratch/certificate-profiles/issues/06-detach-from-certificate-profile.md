# 06: Detach a Managed Certificate from its Certificate Profile

**What to build:** An Organization Administrator detaches a Managed Certificate from its Certificate Profile. It becomes an ordinary Managed Certificate: it keeps its settings and Owners, renews again while the profile stays disabled, and its Name Changes are no longer checked against the profile's name rules.

**Blocked by:** 03, 05

**Status:** done

- [x] A new `managedCertificate.detachProfile` permission, held only by Organization Administrators and reported by `/api/me`.
- [x] Detaching clears the Managed Certificate's link to its profile and changes nothing else. Detaching one with no profile is refused with 409.
- [x] Detaching writes an Audit Event through the `UnitOfWork`, naming the profile.
- [x] A renewal-blocked Managed Certificate is unblocked by detaching, and a due one renews on the next scheduler pass.
- [x] After detaching, a non-administrator's Name Change is no longer checked against the profile's rules, and the profile's disabled state no longer applies.
- [x] The details page has a Detach control for those who hold the permission.
- [x] Server and scheduler tests through the harness.
