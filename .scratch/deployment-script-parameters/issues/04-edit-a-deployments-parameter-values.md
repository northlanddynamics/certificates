# 04: Edit a Deployment's parameter values

**What to build:** An Organization Administrator replaces all of an existing Deployment's parameter values through `PUT .../deployments/{id}/parameters`, so a typo does not mean a new Deployment and a new issuance. The values are validated against the Deployment's pinned version with the same rules as creation. The new `update` action on the `deployment` permission gates it; an Organization Administrator holds it automatically. The edit applies from the next delivery to the Agent; a run already delivered keeps what it was given.

**Blocked by:** 02 (Create a Deployment with parameter values).

**Status:** resolved

- [x] A valid edit replaces the stored values and the next delivery (renewal, manual run or redelivery) carries them
- [x] An invalid edit is refused with `400` and the stored values are unchanged
- [x] A caller without `deployment:update` is refused, and a non-administrator role does not hold it
- [x] An Audit Event names the parameters changed and never their values
- [x] Verified through the HTTP API (Seam A)
