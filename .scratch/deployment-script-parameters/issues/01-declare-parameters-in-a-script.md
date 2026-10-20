# 01: Declare parameters in a Deployment Script

**What to build:** An Organization Administrator uploads a Deployment Script whose content has a `# deploy-params:begin` / `# deploy-params:end` comment block (leading `# ` removed from each inner line, the result a JSON array of `name`, `label`, `description`, `required` and optional `default`). The platform parses it at upload and stores the parsed schema on the script version, inside the hash and immutable. Script and version reads return the schema. A script with no section behaves exactly as before and has an empty schema; existing versions need no backfill.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] A valid section is stored on the version and returned by the script read and the version read
- [ ] Names must match `^[A-Z][A-Z0-9_]*$`, be unique within the script, not start with `DEPLOY_PARAM_`, and number at most 20
- [ ] A malformed section, a duplicate name, an invalid name or more than 20 parameters refuses the upload with `422` naming the problem
- [ ] A script with no section uploads as before and reads back with no parameters; existing versions read back with no parameters
- [ ] Verified through the HTTP API (Seam A) in the deployment-scripts tests
