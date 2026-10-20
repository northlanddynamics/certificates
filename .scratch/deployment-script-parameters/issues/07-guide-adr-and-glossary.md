# 07: Guide, ADR and glossary

**What to build:** Document the feature where people will look for it. The Deployment Scripts guide replaces its "Parameter bindings" section with the new contract: the section format, the field rules, `DEPLOY_PARAM_` variables, blank and default handling, creation and editing, and a worked parameterised example. It warns that values are plain text, that run output is stored (do not echo parameters), and that a script should guard its required parameters because an Agent that predates this change ignores them. A new ADR 0010 records that parameters are plain text on the Deployment and secrets come from the Agent's environment, noting it narrows and does not contradict ADR 0004. `CONTEXT.md` gains "Deployment Parameter" under Deployment.

**Blocked by:** 02 (Create a Deployment with parameter values), 03 (The Agent hands parameters to the script), 04 (Edit a Deployment's parameter values).

**Status:** ready-for-agent

- [ ] The guide's old "no way to pass values per Deployment" text is gone and the new contract matches what shipped
- [ ] The worked example's section format parses with the upload code
- [ ] ADR 0010 states the plain-text decision, why, and the Agent-environment alternative for secrets
- [ ] `CONTEXT.md` defines Deployment Parameter in the glossary's style
