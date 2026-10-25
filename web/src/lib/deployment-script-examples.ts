// The worked examples of the Deployment Scripts guide, which the upload form also offers to start from, and which
// docs/deployment-scripts.md shows as they are. Each is a script in steps, so that the guide can explain it a step at a
// time and the form can join it into one; the step that is `yours` is where the author's own deployment is.
// server/test/script-parameters-web.test.ts checks that each joined script's parameter section is one the platform
// takes, and that the docs carry each one exactly.
import type { DeploymentScript } from "./api";

export interface ExampleStep {
  title: string;
  /** What the step is for, when the code's own comments do not say enough. */
  note?: string;
  code: string;
  /** The place for the author's own deployment. */
  yours?: boolean;
}

export interface ExampleScript {
  id: "nginx" | "app-files" | "iis";
  /** What it deploys to, as its tab and button name it. */
  title: string;
  /** What it does, and what it shows of Deployment Parameters. */
  summary: string;
  interpreter: DeploymentScript["interpreter"];
  /** A name to upload it under. */
  name: string;
  steps: ExampleStep[];
}

const nginx: ExampleScript = {
  id: "nginx",
  title: "nginx site",
  summary: "Puts the Certificate and key where one nginx site reads them, then reloads nginx. It shows a required parameter, one with a default, and an optional one.",
  interpreter: "bash",
  name: "nginx-site",
  steps: [
    {
      title: "Declare what the script needs",
      code: `#!/bin/bash
# Installs the Certificate and its key for one nginx site, then reloads the service.
# deploy-params:begin
# [
#   { "name": "SITE", "label": "Site", "description": "The site's directory under /etc/nginx/certs.", "required": true },
#   { "name": "SERVICE", "label": "Service", "description": "The systemd unit to reload once the files are in place.", "default": "nginx" },
#   { "name": "KEY_OWNER", "description": "The user to give the key file to; it stays the Agent's when blank." }
# ]
# deploy-params:end
set -euo pipefail`,
    },
    {
      title: "Stop if a required one is missing",
      note: "Older Agents run scripts without parameters, so stop if a required one is missing.",
      code: `# An Agent that predates Deployment Parameters runs this without them: stop rather than install to the wrong place.
: "\${DEPLOY_PARAM_SITE:?is not set, so this Agent may predate Deployment Parameters}"
dir="/etc/nginx/certs/$DEPLOY_PARAM_SITE"`,
    },
    {
      title: "Your deployment: put the files where nginx reads them",
      note: "Change these lines to suit your server. $CERT_FULLCHAIN_FILE and $CERT_KEY_FILE are the files to copy. The optional parameter is read with :- so the script doesn't stop when it isn't set.",
      yours: true,
      code: `install -d -m 0755 "$dir"
install -m 0644 "$CERT_FULLCHAIN_FILE" "$dir/fullchain.pem"
install -m 0600 "$CERT_KEY_FILE" "$dir/privkey.pem"
if [ -n "\${DEPLOY_PARAM_KEY_OWNER:-}" ]; then
  chown "$DEPLOY_PARAM_KEY_OWNER" "$dir/privkey.pem"
fi`,
    },
    {
      title: "Reload, and say what was installed",
      note: "The default is repeated here for older Agents. What the script prints is saved, so never print parameter values or secrets.",
      code: `systemctl reload "\${DEPLOY_PARAM_SERVICE:-nginx}"
echo "installed $CERT_FINGERPRINT"`,
    },
  ],
};

const appFiles: ExampleScript = {
  id: "app-files",
  title: "Application files",
  summary: "Copies the Certificate and key into an application's folder, then restarts its Windows service if you name one. It shows a required parameter and an optional one.",
  interpreter: "powershell",
  name: "app-files",
  steps: [
    {
      title: "Declare what the script needs",
      code: `# Copies the Certificate and its key into an application's directory, then restarts its service.
# deploy-params:begin
# [
#   { "name": "TARGET_DIR", "label": "Directory", "description": "Where the application reads certificate.pem and key.pem.", "required": true },
#   { "name": "SERVICE", "label": "Service", "description": "The Windows service to restart; none is restarted when blank." }
# ]
# deploy-params:end
$ErrorActionPreference = 'Stop'`,
    },
    {
      title: "Stop if a required one is missing",
      note: "Older Agents run scripts without parameters, so stop if a required one is missing.",
      code: `# An Agent that predates Deployment Parameters runs this without them: stop rather than write to the wrong place.
if (-not $env:DEPLOY_PARAM_TARGET_DIR) { throw 'TARGET_DIR is not set, so this Agent may predate Deployment Parameters' }`,
    },
    {
      title: "Your deployment: copy the files where the application reads them",
      note: "Change these lines to suit your application. $env:CERT_FULLCHAIN_FILE and $env:CERT_KEY_FILE are the files to copy.",
      yours: true,
      code: `New-Item -ItemType Directory -Force -Path $env:DEPLOY_PARAM_TARGET_DIR | Out-Null
Copy-Item $env:CERT_FULLCHAIN_FILE (Join-Path $env:DEPLOY_PARAM_TARGET_DIR 'certificate.pem') -Force
Copy-Item $env:CERT_KEY_FILE (Join-Path $env:DEPLOY_PARAM_TARGET_DIR 'key.pem') -Force`,
    },
    {
      title: "Restart, and say what was installed",
      note: "An optional parameter left blank isn't set at all, so a simple check is enough. What the script prints is saved, so never print parameter values or secrets.",
      code: `if ($env:DEPLOY_PARAM_SERVICE) { Restart-Service -Name $env:DEPLOY_PARAM_SERVICE }
Write-Output "installed $env:CERT_FINGERPRINT"`,
    },
  ],
};

const iis: ExampleScript = {
  id: "iis",
  title: "IIS site",
  summary: "Adds the Certificate to an IIS site. It shows a required parameter, one with a default, and an optional one, and leaves the IIS steps for you to write.",
  interpreter: "powershell",
  name: "iis-binding",
  steps: [
    {
      title: "Declare what the script needs",
      code: `# Bind a Certificate to an IIS site on this Windows host.
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
$ErrorActionPreference = 'Stop'`,
    },
    {
      title: "Stop if a required one is missing",
      note: "Older Agents run scripts without parameters, so stop if a required one is missing.",
      code: `# An Agent that predates Deployment Parameters runs scripts without them.
if ([string]::IsNullOrEmpty($env:DEPLOY_PARAM_SITE_NAME)) {
  throw 'SITE_NAME is required: update the Agent'
}`,
    },
    {
      title: "Read the other parameters, with defaults",
      code: `$site       = $env:DEPLOY_PARAM_SITE_NAME
$port       = if ($env:DEPLOY_PARAM_PORT) { $env:DEPLOY_PARAM_PORT } else { '443' }
$hostHeader = if ($env:DEPLOY_PARAM_HOST_HEADER) { $env:DEPLOY_PARAM_HOST_HEADER } else { '' }`,
    },
    {
      title: "Pick up the Certificate and key",
      code: `$keyFile       = $env:CERT_KEY_FILE        # the private key, made on this host
$fullchainFile = $env:CERT_FULLCHAIN_FILE  # the leaf, then the intermediates
Write-Output "Deploying $env:CERT_FINGERPRINT for $env:CERT_NAMES"`,
    },
    {
      title: "Your deployment goes here",
      note: "Convert the files into a form IIS can import, add it to the computer's certificate store, and bind it to the site. The Agent uses Windows PowerShell 5.1, which can't read these key files by itself.",
      yours: true,
      code: `# --- your deployment ---------------------------------------------------
# 1. Make a PFX from $fullchainFile and $keyFile
# 2. Import it: Import-PfxCertificate -CertStoreLocation Cert:\\LocalMachine\\My ...
# 3. Bind it to $site on $port (and $hostHeader, with SNI):
#      $binding = Get-WebBinding -Name $site -Protocol https -Port $port
#      $binding.AddSslCertificate($thumbprint, 'My')
# ------------------------------------------------------------------------`,
    },
    {
      title: "Report whether it worked",
      code: `Write-Output "Deployed $env:CERT_FINGERPRINT"  # output is stored: never print values or secrets
exit 0                                         # a throw or any other code fails the run`,
    },
  ],
};

/** The examples, in the order the guide and the upload form offer them. */
export const EXAMPLE_SCRIPTS: ExampleScript[] = [nginx, appFiles, iis];
export const exampleById = (id: ExampleScript["id"]) => EXAMPLE_SCRIPTS.find((e) => e.id === id)!;

/** The example as one script, ready to upload. */
export const exampleContent = (example: ExampleScript) => `${example.steps.map((s) => s.code).join("\n\n")}\n`;

/** The variables the Agent sets for every run, whatever the script declares. */
export const CERT_VARIABLES: { name: string; meaning: string }[] = [
  { name: "CERT_KEY_FILE", meaning: "Where the private key is. It was made on this server, and only the Agent can read it" },
  { name: "CERT_LEAF_FILE", meaning: "Where the Certificate is, on its own" },
  { name: "CERT_CHAIN_FILE", meaning: "Where the intermediate certificates are" },
  { name: "CERT_FULLCHAIN_FILE", meaning: "Where the Certificate and its intermediates are, in one file. Most servers want this one" },
  { name: "CERT_NAMES", meaning: "The names on the Certificate, separated by commas" },
  { name: "CERT_NOT_AFTER", meaning: "When the Certificate expires" },
  { name: "CERT_FINGERPRINT", meaning: "The Certificate's fingerprint, a unique ID for it" },
  { name: "CERT_MANAGED_CERTIFICATE_ID", meaning: "Which Managed Certificate the run is for" },
  { name: "CERT_DEPLOYMENT_ID", meaning: "Which Deployment the run is for" },
];
