# Deployment Scripts

A Deployment Script is the Bash or PowerShell script an Agent runs to put a Certificate to use: copy it where a server reads it, reload the server, push it to a load balancer. Organization Administrators upload them (`/api/organizations/{orgId}/deployment-scripts`, or the Deployment Scripts page in the web app), and only they can read them (ADR 0004). Each upload is a new immutable version, identified by the SHA-256 of its exact content (up to 256 KiB), and a Deployment pins one version for life.

## What a script is given

The Agent runs a script only if the SHA-256 of the content it was given is the version's hash, and only if the Certificate is the one named and its key is on the host. Bash scripts run with `bash`, PowerShell ones with `pwsh` (Linux) or `powershell.exe` (Windows), in the directory the Certificate's files are written to; a script that runs longer than ten minutes is stopped. Its environment is the Agent service's own, plus:

| Variable | Value |
| --- | --- |
| `CERT_KEY_FILE` | Path to the private key, readable only by the Agent's service account |
| `CERT_LEAF_FILE` | Path to the Certificate |
| `CERT_CHAIN_FILE` | Path to the intermediates |
| `CERT_FULLCHAIN_FILE` | Path to the Certificate followed by the intermediates |
| `CERT_MANAGED_CERTIFICATE_ID`, `CERT_DEPLOYMENT_ID` | The Managed Certificate and the Deployment |
| `CERT_FINGERPRINT` | SHA-256 of the Certificate, hex |
| `CERT_NAMES` | Its names, comma-separated |
| `CERT_NOT_AFTER` | When it ends |
| `DEPLOY_PARAM_<NAME>` | Each Deployment Parameter that has a value (below) |

The exit code says whether it succeeded: 0 is a success, anything else a failed Deployment Run. Its output (standard output and standard error together, the first 32 KiB) is stored with the run on the platform, where every Organization Administrator can read it.

## Deployment Parameters

A script that puts Certificates in many places declares the values that differ between them, its Deployment Parameters, and each Deployment gives them: one script then serves any site, port or pool. Values are plain text, stored on the Deployment and visible to every Organization Administrator, so a parameter is no place for a secret (ADR 0010). A password, an API token or a key the script needs comes from the Agent service's environment on the host, which the script inherits, as before.

### Declaring them

The parameters are declared in the script, in one comment block from a `# deploy-params:begin` line to a `# deploy-params:end` line. With each line's leading `# ` removed, what is between them is a JSON array, one object per parameter. `#` begins a comment in Bash and PowerShell alike, so the interpreter never runs it, and one format serves both. A script with no such block has no parameters.

| Field | | |
| --- | --- | --- |
| `name` | required | Upper-case letters, digits and `_`, starting with a letter (`^[A-Z][A-Z0-9_]*$`); not starting with `DEPLOY_PARAM_`; once per script |
| `label` | optional | What the form shows for it; the name when there is none |
| `description` | optional | Shown as help under the field |
| `required` | optional | `true` or `false`, default `false` |
| `default` | optional | A string, the value used when none is given; it obeys the rules for values below |

A script declares at most 20 parameters, and no other field (no type, pattern or list of options: every value is text). The block is part of the content, so it is inside the hash: changing a declaration is uploading a new version, and a version's parameters never change. An upload whose block cannot be used is refused with `422`, saying why: a second block, a missing or stray end line, a line inside the block that is neither blank nor a comment, JSON that does not parse or is not an array of parameters, an unknown field, an invalid or repeated name, more than 20 parameters, or a default that breaks the rules for values. Reading a script or one of its versions returns `parameters`, what it declares, in order.

### Giving the values

Creating a Deployment (`POST /api/organizations/{orgId}/deployments`, or Set up a Deployment under Deployments in the web app) takes `parameters`, an object of name to value, for the version chosen; the dialog shows one field per parameter of that version, with the default filled in. They are checked before anything is made:

- A value is a string of at most 1 KiB, with no NUL and no newline.
- A name the version does not declare is refused, so a misspelt one is not ignored.
- A blank value (empty, or only spaces) counts as not given. A parameter not given takes its default; one still blank is left unset, and a required one is refused.

A refusal is a `400` whose `parameters` says, by name, what is wrong with each parameter at fault. The Deployment keeps the values it was given, after the defaults, and every run uses them: the first, each renewal, and each run again.

To change them, replace them all (`PUT /api/organizations/{orgId}/deployments/{id}/parameters`, or Parameters, then Edit values, on the Deployment in the web app). The new values are checked against the version the Deployment is pinned to, by the same rules, and need the `deployment:update` permission, which only an Organization Administrator holds. They apply to every run given to the Agent from then on, including a run given again because it was never reported; a run the Agent already has keeps what it was given. Creating a Deployment with parameters, and each change to them, is an Audit Event that names the parameters, never their values (`deployment.created`'s `parameters`, `deployment.parameters_changed`).

### Reading them in the script

The Agent gives each value as the variable `DEPLOY_PARAM_` and the name: `SITE_ID` is `DEPLOY_PARAM_SITE_ID`. A parameter with no value is absent, never set to an empty string, so the usual tests work: `${DEPLOY_PARAM_PORT:-443}` in Bash, `if ($env:DEPLOY_PARAM_PORT)` in PowerShell. The values win: the Agent drops any `DEPLOY_PARAM_` variable from its own environment before running a script, so a script sees only the Deployment's. The Agent refuses a run whose parameter names are not ones a script can be given, reporting it failed without running the script.

Two things to write into every script that has parameters:

- **Guard the required ones.** An Agent older than Deployment Parameters ignores them and runs the script without them, and nothing tells the platform so. Check each required parameter at the top and fail if it is missing, as the examples do, so such a run fails loudly rather than putting the Certificate in the wrong place. For the same reason, fall back to the default in the script too.
- **Do not print them.** The output is stored with the run and read by every Organization Administrator, so a script that echoes its parameters, its environment (`env`, `set -x`, `Get-ChildItem env:`) or a secret makes a second copy of them there.

### Worked examples

The three examples below are also in the web app: the Deployment Scripts guide shows each a step at a time, with the step that is your own deployment marked, and the upload dialog can start from any of them. They are the same scripts in both places.

#### Bash: an nginx site

This script installs the Certificate for one nginx site and reloads nginx. Each Deployment of it names the site; the unit to reload and the key file's owner are optional.

```bash
#!/bin/bash
# Installs the Certificate and its key for one nginx site, then reloads the service.
# deploy-params:begin
# [
#   { "name": "SITE", "label": "Site", "description": "The site's directory under /etc/nginx/certs.", "required": true },
#   { "name": "SERVICE", "label": "Service", "description": "The systemd unit to reload once the files are in place.", "default": "nginx" },
#   { "name": "KEY_OWNER", "description": "The user to give the key file to; it stays the Agent's when blank." }
# ]
# deploy-params:end
set -euo pipefail

# An Agent that predates Deployment Parameters runs this without them: stop rather than install to the wrong place.
: "${DEPLOY_PARAM_SITE:?is not set, so this Agent may predate Deployment Parameters}"
dir="/etc/nginx/certs/$DEPLOY_PARAM_SITE"

install -d -m 0755 "$dir"
install -m 0644 "$CERT_FULLCHAIN_FILE" "$dir/fullchain.pem"
install -m 0600 "$CERT_KEY_FILE" "$dir/privkey.pem"
if [ -n "${DEPLOY_PARAM_KEY_OWNER:-}" ]; then
  chown "$DEPLOY_PARAM_KEY_OWNER" "$dir/privkey.pem"
fi

systemctl reload "${DEPLOY_PARAM_SERVICE:-nginx}"
echo "installed $CERT_FINGERPRINT"
```

A Deployment created with `"parameters": { "SITE": "shop", "KEY_OWNER": "" }` keeps `{ "SITE": "shop", "SERVICE": "nginx" }`: the blank owner is left unset and the service takes its default. The script then sees `DEPLOY_PARAM_SITE=shop` and `DEPLOY_PARAM_SERVICE=nginx`, and no `DEPLOY_PARAM_KEY_OWNER`. `"parameters": {}` is refused, as `SITE` is required.

#### PowerShell: an application's files

The same format in a PowerShell script, which copies the files into an application's directory and restarts its Windows service when one is named.

```powershell
# Copies the Certificate and its key into an application's directory, then restarts its service.
# deploy-params:begin
# [
#   { "name": "TARGET_DIR", "label": "Directory", "description": "Where the application reads certificate.pem and key.pem.", "required": true },
#   { "name": "SERVICE", "label": "Service", "description": "The Windows service to restart; none is restarted when blank." }
# ]
# deploy-params:end
$ErrorActionPreference = 'Stop'

# An Agent that predates Deployment Parameters runs this without them: stop rather than write to the wrong place.
if (-not $env:DEPLOY_PARAM_TARGET_DIR) { throw 'TARGET_DIR is not set, so this Agent may predate Deployment Parameters' }

New-Item -ItemType Directory -Force -Path $env:DEPLOY_PARAM_TARGET_DIR | Out-Null
Copy-Item $env:CERT_FULLCHAIN_FILE (Join-Path $env:DEPLOY_PARAM_TARGET_DIR 'certificate.pem') -Force
Copy-Item $env:CERT_KEY_FILE (Join-Path $env:DEPLOY_PARAM_TARGET_DIR 'key.pem') -Force

if ($env:DEPLOY_PARAM_SERVICE) { Restart-Service -Name $env:DEPLOY_PARAM_SERVICE }
Write-Output "installed $env:CERT_FINGERPRINT"
```

#### PowerShell: an IIS site

This one binds the Certificate to an IIS site, and leaves the binding itself for you to write: on Windows the Agent runs `powershell.exe` (5.1), which cannot read a PEM key, so the files are first made into a PFX. Each Deployment names the site; the port defaults to 443, and a blank host name binds every one.

```powershell
# Bind a Certificate to an IIS site on this Windows host.
#
# deploy-params:begin
# [
#   { "name": "SITE_NAME", "label": "IIS site", "required": true,
#     "description": "The site's name in IIS Manager." },
#   { "name": "PORT", "label": "HTTPS port", "default": "443" },
#   { "name": "HOST_HEADER", "label": "Host name",
#     "description": "For SNI. Leave blank to bind every host name." }
# ]
# deploy-params:end
$ErrorActionPreference = 'Stop'

# An Agent that predates Deployment Parameters runs scripts without them.
if ([string]::IsNullOrEmpty($env:DEPLOY_PARAM_SITE_NAME)) {
  throw 'SITE_NAME is required: update the Agent'
}

$site       = $env:DEPLOY_PARAM_SITE_NAME
$port       = if ($env:DEPLOY_PARAM_PORT) { $env:DEPLOY_PARAM_PORT } else { '443' }
$hostHeader = if ($env:DEPLOY_PARAM_HOST_HEADER) { $env:DEPLOY_PARAM_HOST_HEADER } else { '' }

$keyFile       = $env:CERT_KEY_FILE        # the private key, made on this host
$fullchainFile = $env:CERT_FULLCHAIN_FILE  # the leaf, then the intermediates
Write-Output "Deploying $env:CERT_FINGERPRINT for $env:CERT_NAMES"

# --- your deployment ---------------------------------------------------
# 1. Make a PFX from $fullchainFile and $keyFile
# 2. Import it: Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My ...
# 3. Bind it to $site on $port (and $hostHeader, with SNI):
#      $binding = Get-WebBinding -Name $site -Protocol https -Port $port
#      $binding.AddSslCertificate($thumbprint, 'My')
# ------------------------------------------------------------------------

Write-Output "Deployed $env:CERT_FINGERPRINT"  # output is stored: never print values or secrets
exit 0                                         # a throw or any other code fails the run
```
