# 02: Create a Deployment with parameter values

**What to build:** Creating a Deployment accepts `parameters`, a name-to-value object, and validates it against the pinned script version's schema before anything is created. The values are stored on the Deployment in plain text and returned on Deployment reads. The Agent's Deployment work item carries them as `parameters` at every delivery: the first run, each renewal, "run again", and the redelivery of a run never reported. An Audit Event names the parameters set, never the values.

**Blocked by:** 01 (Declare parameters in a Deployment Script).

**Status:** ready-for-agent

- [ ] A missing required value, a value for an undeclared name, a value over 1 KiB, or a value containing NUL or a newline is refused with `400` naming the parameters at fault, and no Deployment is created
- [ ] A blank optional value counts as not provided: `default` is applied first, and a value still blank is left out
- [ ] The stored values come back on Deployment reads and on no read by a non-administrator
- [ ] The work item carries the values for the first delivery, a renewal, a manual run and a redelivery
- [ ] Existing Deployments read back with no values and keep working
- [ ] The creation Audit Event lists parameter names and no values
- [ ] Verified through the HTTP API with the stand-in Agent (Seam A) in the first-deployment tests
