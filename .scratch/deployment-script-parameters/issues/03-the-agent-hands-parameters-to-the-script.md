# 03: The Agent hands parameters to the script

**What to build:** When the work item carries `parameters`, the Go Agent gives the script each value as an environment variable named `DEPLOY_PARAM_` plus the name, adding the prefix itself. The values go in after the inherited environment, so they win over a same-named Agent variable. A name outside `^[A-Z][A-Z0-9_]*$` fails the run, reported with the reason, and the script is not run. The hash check and the Certificate checks stay first and unchanged. An unset optional parameter is simply absent.

**Blocked by:** None (can start immediately). It needs only the agreed `parameters` field on the work item (a name-to-value object).

**Status:** resolved

- [x] The script sees `DEPLOY_PARAM_<NAME>` for each value in the work item
- [x] A name that fails the charset reports the run as failed with the reason and does not run the script; `PATH` or `LD_PRELOAD` cannot be set this way
- [x] A platform value overrides an inherited variable of the same name
- [x] A parameter not in the work item is absent from the environment
- [x] A work item with no `parameters` runs exactly as before
- [x] Verified in the Go Agent tests (Seam B) beside the existing script-environment test
