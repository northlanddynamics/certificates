Status: ready-for-agent

# Deployment Script parameters

## Problem Statement

An Organization Administrator who deploys a Certificate to a target such as a load balancer or a site on a web server often needs to give the Deployment Script values specific to that target: a site id, a port, a pool name. Today the only values a script receives are the `CERT_*` variables. The administrator must write the target-specific value into the script, which needs a new script version and a new Deployment for every target, or set it in the Agent service's environment on the host, where the platform cannot see it, validate it or show it. Scripts that differ only by one value end up duplicated.

## Solution

A Deployment Script declares the parameters it needs in a parsable section of its own content. When the administrator creates a Deployment, the form shows one input for each declared parameter, and the platform checks the values before it accepts the Deployment. The values are stored on the Deployment and reused for every renewal and every manual run. The script receives each value as an environment variable named after the parameter with a fixed prefix (`DEPLOY_PARAM_SITE_ID`). One script can then serve many targets.

Values are plain text, visible to Organization Administrators, stored on the Deployment. Anything secret still comes from the Agent's own environment, as now.

## User Stories

1. As an Organization Administrator, I want a Deployment Script to declare the parameters it needs, so that the platform can ask me for them when I create a Deployment.
2. As an Organization Administrator, I want the declaration to live inside the script, so that the script and its requirements are written, reviewed and versioned together.
3. As an Organization Administrator, I want an upload with a malformed parameter section refused with a clear message, so that I find the mistake when I upload and not when a Deployment fails.
4. As an Organization Administrator, I want an upload that declares the same parameter name twice refused, so that a parameter always means one thing.
5. As an Organization Administrator, I want an upload with an invalid parameter name refused, so that every name can become a safe environment variable.
6. As an Organization Administrator, I want an upload that declares more than 20 parameters refused, so that a script's inputs stay reviewable.
7. As an Organization Administrator, I want a script with no parameter section to keep working exactly as before, so that my existing scripts and Deployments are unaffected.
8. As an Organization Administrator, I want each parameter to have a name, a label, a description and a required flag, so that the form can tell me what to enter and why.
9. As an Organization Administrator, I want a parameter to be able to carry a default, so that the form is pre-filled with the usual value.
10. As an Organization Administrator, I want the label to fall back to the name when none is given, so that a terse declaration still produces a usable form.
11. As an Organization Administrator, I want the script's parameters returned when I read a script or one of its versions, so that I can see what a version needs before I choose it.
12. As an Organization Administrator, I want the declaration to be part of the version's hash and never change, so that a Deployment pinned to a version always means the same inputs.
13. As an Organization Administrator, I want the Deployment form to show one text input for each declared parameter of the version I chose, so that I do not have to know the names.
14. As an Organization Administrator, I want required inputs marked and their descriptions shown as help, so that I fill them in correctly.
15. As an Organization Administrator, I want values I typed kept for names that still exist when I switch script version in the form, so that I do not retype them.
16. As an Organization Administrator, I want a missing required value refused when I create the Deployment, so that a Deployment never exists that its script cannot run.
17. As an Organization Administrator, I want a value for an undeclared name refused, so that a typo in a name is caught and not silently ignored.
18. As an Organization Administrator, I want a value that is too long, contains a NUL or contains a newline refused, so that it is always safe to put in an environment variable.
19. As an Organization Administrator, I want a blank optional value treated as not provided, so that the script can tell "unset" from "set to something".
20. As an Organization Administrator, I want a parameter's default used when I leave it blank, so that defaults behave as the form showed.
21. As an Organization Administrator, I want the values given once at creation and reused for every renewal, so that automatic renewals need nobody.
22. As an Organization Administrator, I want "run again" to use the stored values, so that a manual run behaves like a renewal.
23. As an Organization Administrator, I want to see a Deployment's stored values, so that I can check what a script is being given.
24. As an Organization Administrator, I want to replace the values on an existing Deployment, so that fixing a typo does not mean creating a new Deployment and a new issuance.
25. As an Organization Administrator, I want an edit validated against the Deployment's pinned version, so that edits obey the same rules as creation.
26. As an Organization Administrator, I want an edit to take effect from the next delivery to the Agent, so that I know when it applies.
27. As an Organization Administrator, I want creating a Deployment with parameters and editing them to be recorded as Audit Events that name the parameters and not their values, so that the audit trail does not become a second copy of the values.
28. As an Organization Administrator, I want only holders of a new `deployment:update` permission to edit values, so that this stays an Organization Administrator action and any later role gets it only on purpose.
29. As an Approver or Member, I want no access to Deployment values, so that parameters cannot leak to roles that cannot see Deployments today.
30. As a script author, I want each parameter in an environment variable named `DEPLOY_PARAM_` plus its name, so that it matches the existing `CERT_*` variables and needs no quoting.
31. As a script author, I want an unset optional parameter to be absent from the environment, so that `${DEPLOY_PARAM_PORT:-443}` in Bash and an emptiness test in PowerShell both work.
32. As a script author, I want the documentation to tell me to guard required parameters in the script, so that a script run by an Agent that predates this feature fails loudly and not silently.
33. As a script author, I want the documentation to say that run output is stored on the platform, so that I do not echo parameters.
34. As a script author, I want a worked example of a parameterised script, so that I can copy the section format correctly.
35. As an Agent operator, I want the Agent to add the prefix itself and refuse any name outside the allowed characters, so that a bad value from the platform cannot set `PATH` or `LD_PRELOAD`.
36. As an Agent operator, I want a platform-supplied value to win over a variable of the same name in the Agent's own environment, so that the Deployment's setting is what the script sees.
37. As an Agent operator, I want the Agent to keep running the script only if its hash matches, exactly as now, so that this feature does not weaken that check.
38. As a security reviewer, I want it recorded that parameters are plain text on the Deployment and secrets come from the Agent's environment, so that nobody later assumes parameters are a safe place for secrets.
39. As an Organization Administrator, I want a redelivered run (one delivered but never reported) to be given the current values, so that it behaves like any other delivery.

## Implementation Decisions

- **Declaration.** A comment block in the script delimited by `# deploy-params:begin` and `# deploy-params:end`. The leading `# ` is removed from each line inside and the result is a JSON array. `#` is a line comment in both Bash and PowerShell, so one format serves both interpreters. A missing section means no parameters.
- **Parsing and storage.** The platform parses the section at upload and stores the parsed array on the script version. The section is part of the content, so it is inside the hash and immutable with the version; the earlier idea of keeping the declaration outside the hash is dropped. The Agent never parses it. Existing versions get an empty schema; no backfill.
- **Parameter fields.** `name`, `label`, `description`, `required`, and an optional `default`. All are strings except `required`. No `type`, `pattern` or option lists. Every control is a text input.
- **Names.** Match `^[A-Z][A-Z0-9_]*$`, unique within a script, must not start with the prefix, at most 20 per script. The environment variable is `DEPLOY_PARAM_` plus the name.
- **Values.** Strings of at most 1 KiB, with no NUL and no newline. Unknown names are refused. A missing required value is refused. A blank optional value counts as not provided; the default is applied first, and a value still blank is left unset.
- **Upload failures.** A malformed section, a duplicate name, an invalid name or too many parameters refuses the upload with `422`, naming the problem.
- **Stored values.** A column on the Deployment holding a name-to-value map, plain text. Existing Deployments get an empty map. Because a Deployment pins its script version for life, the schema it was validated against never changes under it, so renewals reuse the values without re-validation drift.
- **Create.** The Deployment creation body takes `parameters` as a name-to-value object, validated against the chosen version's schema before anything is created. A failure is a `400` naming the parameters at fault.
- **Reads.** Script and version reads return the parsed parameters. Deployment reads return the stored values. Both are already limited to Organization Administrators by the `deploymentScript` and `deployment` read permissions.
- **Edit.** A route that replaces all of a Deployment's values, validated against its pinned version. It needs a new `update` action on the `deployment` permission, which an Organization Administrator holds automatically. The change applies to work items delivered after it; a run already delivered keeps what it was given. Runs do not record values.
- **Audit Events.** Creating a Deployment with parameters and editing them each write an Audit Event naming the parameters set or changed, never the values.
- **Work item.** The Agent's Deployment work item carries a `parameters` object of name-to-value. It is read from the Deployment at each delivery, including the redelivery of a run never reported.
- **Agent.** Adds the `DEPLOY_PARAM_` prefix itself, refuses any name that fails the charset (reporting the run as failed with the reason, without running the script), and puts the values in the script's environment after its inherited environment, so they win. The hash check and the Certificate checks are unchanged and run first.
- **Agent version skew.** There is no version handshake. An Agent that predates this change ignores `parameters` and runs the script without them. The documentation tells script authors to guard required parameters in the script so that case fails loudly.
- **Web.** The Deployment dialog renders one input per declared parameter once a script version is chosen, using the existing form components: the label (or the name), the description as help text, a required marker and the default pre-filled. Values for names that survive a version switch are kept. The form checks required fields before submit and the server stays the authority. The Deployment's page gets a control to edit the values using the same fields.
- **Documentation.** The "Parameter bindings" section of the Deployment Scripts guide is replaced with the new contract and a parameterised example, with warnings that values are plain text and that run output is stored. A new ADR records that parameters are plain text on the Deployment and secrets come from the Agent's environment. This does not contradict ADR 0004; it narrows what the guide says about per-Deployment values.
- **Glossary.** If `CONTEXT.md` has no term for these values, add "Deployment Parameter" under Deployment, defined as a named value an Organization Administrator gives a Deployment, declared by its Deployment Script version and handed to the script as an environment variable.

## Testing Decisions

- A good test checks behaviour that someone outside the module can see: the API's responses, the work item the Agent is given, the environment a script sees, the Audit Events written. It does not check how the parser is structured or which function builds the environment.
- **Seam A, the platform's HTTP API.** Tests through the harness with an Organization Administrator and the stand-in Agent. They cover: upload with a good section and the schema coming back on reads; every `422` case; a script with no section; create with good values, a missing required value, an unknown name, an over-long value, a NUL, a newline, a blank optional and a default; stored values reused by a renewal and by "run again"; the work item carrying the values; edit with the same validation and the new permission; an edit reaching the next delivery; the Audit Events naming parameters without values; a non-administrator unable to read or edit values.
- **Seam B, the Go Agent.** Tests alongside the existing script-environment test: the values appear as `DEPLOY_PARAM_*`; a name outside the charset is refused and the script is not run; a platform value overrides an inherited variable of the same name; an unset optional parameter is absent.
- **Not tested automatically:** the web form. `web/` has no test runner and one is not added for this; the dialog and the edit control are checked by hand.
- **Prior art:** `deployment-scripts.test.ts` for uploads and versions, `first-deployment.test.ts` for creating a Deployment and the work item, and `deploy_test.go`'s test that the script runs with the Certificate files and identifiers in its environment.

## Out of Scope

- Secret parameters, encrypted storage or masking in the form. Values are plain text for now; the schema leaves room for a later `secret` flag.
- Parameter types, patterns, option lists or cross-field rules.
- Parameters changing the pinned script version, or any route to re-pin a Deployment.
- A per-run record of the values used.
- An Agent version handshake or a capability report.
- Parameters for anything other than Deployment Scripts.
- Automated tests of the web form.

## Further Notes

- The Agent's environment is inherited by scripts, so the platform-wins rule is a deliberate choice, not an accident of ordering.
- The stored run output can include anything a script prints; the guide already warns against printing secrets and should add parameters to that warning.
- Suggested slices for the issue tracker: the declaration and upload parsing; creating a Deployment with validated values; the Agent's environment; editing values; the web form; the guide, ADR and glossary.
