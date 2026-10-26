# 07: Name Change and Revocation from the portal

**What to build:** From a Managed Certificate in the portal, an Owner proposes a Name Change, with a new CSR made in the browser or pasted, checked against its Certificate Profile's name rules, and then sees it waiting for Approval. When a key is exposed, the Owner revokes the current Certificate with a reason chosen in plain words.

**Blocked by:** 06 (Managed Certificate in the portal)

**Status:** ready-for-agent

- [ ] Built on the existing Name Change and Revocation endpoints; no new server behaviour.
- [ ] A Name Change reuses the request flow's names and key steps from 05, held to the profile's current name rules.
- [ ] A pending Name Change shows on the Managed Certificate, and a rejected one says why.
- [ ] Revocation asks for confirmation and a reason, offering only the reasons its CA takes, described in plain words.
- [ ] Both are offered only when Ownership or `/api/me` permissions allow, and are refused as the API refuses them.
- [ ] Works at phone width.
