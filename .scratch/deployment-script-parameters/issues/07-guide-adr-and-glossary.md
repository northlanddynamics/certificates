# 07: Guide, ADR and glossary

**What to build:** Document the feature where people will look for it. The Deployment Scripts guide replaces its "Parameter bindings" section with the new contract: the section format, the field rules, `DEPLOY_PARAM_` variables, blank and default handling, creation and editing, and a worked parameterised example. It warns that values are plain text, that run output is stored (do not echo parameters), and that a script should guard its required parameters because an Agent that predates this change ignores them. A new ADR 0010 records that parameters are plain text on the Deployment and secrets come from the Agent's environment, noting it narrows and does not contradict ADR 0004. `CONTEXT.md` gains "Deployment Parameter" under Deployment.

**Blocked by:** 02 (Create a Deployment with parameter values), 03 (The Agent hands parameters to the script), 04 (Edit a Deployment's parameter values).

**Status:** resolved

- [x] The guide's old "no way to pass values per Deployment" text is gone and the new contract matches what shipped
- [x] The worked example's section format parses with the upload code
- [x] ADR 0010 states the plain-text decision, why, and the Agent-environment alternative for secrets
- [x] `CONTEXT.md` defines Deployment Parameter in the glossary's style

## Comments

- The repo had no Deployment Scripts guide (and so no "Parameter bindings" section); the README's Deployment paragraphs were the only documentation. The guide is new, `docs/deployment-scripts.md`, linked from the README, which also names the `DEPLOY_PARAM_` variables beside the `CERT_*` ones. It has a Bash and a PowerShell worked example; `deployment-scripts.test.ts` uploads both from the guide and checks what they declare, so the examples cannot drift from the parser. ADR 0010 and the `CONTEXT.md` term are added. The test runs in the PR's CI: this environment cannot run it.
