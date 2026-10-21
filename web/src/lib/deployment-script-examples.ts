// The worked examples of the Deployment Scripts guide, which the upload form also offers to start from. Each is a
// script in steps, so that the guide can explain it a step at a time and the form can join it into one; the step that
// is `yours` is where the author puts their own deployment. server/test/script-parameters-web.test.ts checks that each
// joined script's parameter section is one the platform takes.
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
  interpreter: DeploymentScript["interpreter"];
  /** A name to upload it under. */
  name: string;
  steps: ExampleStep[];
}

const bash: ExampleScript = {
  interpreter: "bash",
  name: "nginx-site",
  steps: [
    {
      title: "Declare what the script needs",
      code: `#!/usr/bin/env bash
# Put a Certificate on an nginx site, on this host or another.
#
# deploy-params:begin
# [
#   { "name": "SITE_NAME", "label": "Site name", "required": true,
#     "description": "The nginx site the Certificate is for, as in sites-enabled." },
#   { "name": "TARGET_HOST", "label": "Target host",
#     "description": "Leave blank to deploy on the Agent's own host." },
#   { "name": "CERT_DIR", "label": "Certificate directory",
#     "default": "/etc/ssl/platform" },
#   { "name": "RELOAD", "label": "Reload nginx", "default": "yes",
#     "description": "yes or no." }
# ]
# deploy-params:end
set -euo pipefail`,
    },
    {
      title: "Guard the required ones",
      note: "The platform refuses a Deployment without them, but an Agent that predates script parameters runs the script without any.",
      code: `# An Agent that predates script parameters runs scripts without them:
# stop here, loudly, rather than deploy to the wrong place.
: "\${DEPLOY_PARAM_SITE_NAME:?SITE_NAME is required: update the Agent}"`,
    },
    {
      title: "Read the rest, with a fallback for each",
      code: `# A blank optional parameter is absent, and set -u stops on an unset
# variable, so always read them with :-
site="$DEPLOY_PARAM_SITE_NAME"
target="\${DEPLOY_PARAM_TARGET_HOST:-}"
cert_dir="\${DEPLOY_PARAM_CERT_DIR:-/etc/ssl/platform}"
reload="\${DEPLOY_PARAM_RELOAD:-yes}"`,
    },
    {
      title: "Pick up the Certificate and key",
      code: `key="$CERT_KEY_FILE"              # the private key, made on this host
fullchain="$CERT_FULLCHAIN_FILE"  # the leaf, then the intermediates
echo "Deploying $CERT_FINGERPRINT for $CERT_NAMES, valid until $CERT_NOT_AFTER"`,
    },
    {
      title: "Your deployment goes here",
      note: "Put $key and $fullchain where the service reads them, then reload it. Credentials for other hosts come from the Agent's own environment, never from a parameter.",
      yours: true,
      code: `# --- your deployment ---------------------------------------------------
# For example, to another host over SSH, with a key path set in the
# Agent service's environment as NGINX_DEPLOY_SSH_KEY:
#
#   dest="$target:$cert_dir/$site"
#   scp -i "$NGINX_DEPLOY_SSH_KEY" "$fullchain" "$dest/fullchain.pem"
#   scp -i "$NGINX_DEPLOY_SSH_KEY" "$key"       "$dest/privkey.pem"
#   if [ "$reload" = yes ]; then
#     ssh -i "$NGINX_DEPLOY_SSH_KEY" "$target" 'nginx -t && systemctl reload nginx'
#   fi
# ------------------------------------------------------------------------`,
    },
    {
      title: "Exit with the outcome",
      code: `echo "Deployed $CERT_FINGERPRINT"   # output is stored: never print parameter values or secrets
exit 0                              # any other code marks the Deployment Run failed`,
    },
  ],
};

const powershell: ExampleScript = {
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
      title: "Guard the required ones",
      note: "The platform refuses a Deployment without them, but an Agent that predates script parameters runs the script without any.",
      code: `# An Agent that predates script parameters runs scripts without them.
if ([string]::IsNullOrEmpty($env:DEPLOY_PARAM_SITE_NAME)) {
  throw 'SITE_NAME is required: update the Agent'
}`,
    },
    {
      title: "Read the rest, with a fallback for each",
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
      note: "Turn the PEM files into what IIS imports, put it in the machine store and bind it. On Windows the Agent runs powershell.exe (5.1), which cannot read PEM keys itself.",
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
      title: "Exit with the outcome",
      code: `Write-Output "Deployed $env:CERT_FINGERPRINT"  # output is stored: never print values or secrets
exit 0                                         # a throw or any other code fails the run`,
    },
  ],
};

export const EXAMPLE_SCRIPTS: Record<DeploymentScript["interpreter"], ExampleScript> = { bash, powershell };

/** The example as one script, ready to upload. */
export const exampleContent = (example: ExampleScript) => `${example.steps.map((s) => s.code).join("\n\n")}\n`;

/** The variables the Agent sets for every run, whatever the script declares. */
export const CERT_VARIABLES: { name: string; meaning: string }[] = [
  { name: "CERT_KEY_FILE", meaning: "Path to the private key, made on this host and readable only by the Agent's service account" },
  { name: "CERT_LEAF_FILE", meaning: "Path to the Certificate alone" },
  { name: "CERT_CHAIN_FILE", meaning: "Path to the intermediates" },
  { name: "CERT_FULLCHAIN_FILE", meaning: "Path to the leaf followed by the intermediates" },
  { name: "CERT_NAMES", meaning: "The Certificate's names, comma-separated" },
  { name: "CERT_NOT_AFTER", meaning: "When the Certificate ends" },
  { name: "CERT_FINGERPRINT", meaning: "The Certificate's SHA-256 fingerprint" },
  { name: "CERT_MANAGED_CERTIFICATE_ID", meaning: "Which Managed Certificate the run is for" },
  { name: "CERT_DEPLOYMENT_ID", meaning: "Which Deployment the run is for" },
];
