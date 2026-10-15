# Spec: Certificate Management Platform v1

Status: ready-for-agent

## Problem Statement

TLS certificate lifetimes and domain-validation reuse periods keep getting shorter, so every certificate needs attention more often. Today that attention is manual: teams ask for certificates by hand, install them by hand, and find out about expiry when something breaks. The inventory is spread across teams and tools, so nobody can confidently answer "which certificates do we have, who is responsible for each, and when do they expire?" The current commercial tool (DigiCert Trust Lifecycle Manager) is expensive, and it doesn't remove enough of the manual effort to justify its cost.

The people affected:

- **Application teams** who need certificates for apps the platform can't automate. They want to request a certificate, get it approved, and download it, without filing tickets or emailing PKI specialists.
- **Organization Administrators** who need to control which names get certificates, see the whole inventory, and set up automation that renews and installs certificates on hosts without anyone touching them.
- **Approvers** (often security) who need to decide which names may be issued, without needing full administrative control.
- **Platform Operators** who run the service for several unrelated Organizations and need them to stay strictly separated.

## Solution

A hosted, multi-Organization web platform for issuing and renewing TLS certificates through ACME (Let's Encrypt in v1). It has two halves:

1. **A web portal and API.** Users create **Managed Certificates**, get **Approval** for their names, configure each certificate's **Renewal Policy**, download issued **Certificates** in several formats, revoke them, and subscribe to notices. The platform performs **Domain Control Validation** against the Organization's own DNS, either **Direct** or **Delegated** through the Organization's own **Validation Zone**, using pluggable **DNS Providers** (Infoblox and RFC 2136 in v1).
2. **A cross-platform Agent** (a single Go binary for Windows and Linux) that each Organization installs inside its own network. The Agent:
   - generates private keys locally, so they never reach the platform
   - receives the issued Certificates and runs **Deployment Scripts** written by Organization Administrators to install them wherever they're needed
   - relays DNS Provider operations to internal DNS that the hosted platform can't reach

The platform **never holds private keys**. The key either stays with the Owner, who submits a CSR, or with exactly one Agent. Every change to the platform's state goes into an append-only audit log that can be exported to a SIEM. Identity (passwords with MFA, passkeys, OIDC, SAML, Organizations, Teams, roles, API keys, impersonation) is handled entirely by Better Auth.

## User Stories

### Platform operation and tenancy

1. As a Platform Operator, I want to create an Organization and invite its first Organization Administrator, so that a new customer can start using the platform.
2. As a Platform Operator, I want Organizations to be created only by me (no self-service signup), so that I control who uses the platform before it is publicly hardened.
3. As a Platform Operator, I want to suspend an Organization, so that I can stop all of its issuance and Agent activity if I need to.
4. As a Platform Operator, I want to see a list of Organizations with basic usage counts (Managed Certificates, Agents, users), so that I can operate the service without seeing inside any Organization.
5. As a Platform Operator, I want to be unable to see an Organization's Managed Certificates, scripts or settings unless I've been explicitly invited into it, so that customers can trust the separation.
6. As a Platform Operator, I want to impersonate a user through Better Auth, so that I can reproduce and diagnose support issues.
7. As an Organization Administrator, I want my Organization's data, ACME accounts, DNS Provider credentials, Validation Zones, Agents and scripts to be completely isolated from other Organizations, so that no other tenant can see or use them.

### Identity and access

8. As a user, I want to sign in with a username and password plus MFA (TOTP), so that my account is protected even if my password leaks.
9. As a user, I want to sign in with a passkey, so that I can log in quickly without a password.
10. As a user in an Organization with SSO, I want to sign in through my company's SAML identity provider (for example Ping) or an OIDC provider, so that I use my corporate identity.
11. As an Organization Administrator, I want to set up a SAML or OIDC connection that belongs only to my Organization, so that our employees can sign in with our identity provider.
12. As a new employee signing in through SSO for the first time, I want my account created automatically as a Member of the linked Organization, so that I don't have to wait for an invitation.
13. As an Organization Administrator, I want to require SSO for my Organization, so that password logins are blocked for our users.
14. As an Organization Administrator, I want to require MFA for password users, so that no account in my Organization relies on a password alone.
15. As an Organization Administrator, I want to invite users by email and give them the Member, Approver or Organization Administrator role, so that I control who can do what.
16. As an Organization Administrator, I want to create Teams and add users to them, so that Managed Certificates can be owned by a group rather than one person.
17. As an Organization Administrator, I want to remove a user from the Organization, so that people who leave lose access. Removing them also takes them off every Managed Certificate's Owners and Subscribers.
18. As a user, I want to create API keys that carry my permissions, so that scripts and CI pipelines can call the platform API without an Agent.
19. As an Organization Administrator, I want every API key's use to be audited, so that I can trace automated actions back to a person.

### Visibility

20. As a Member, I want to see the Managed Certificates I own, directly or through a Team, so that I can focus on what I'm responsible for.
21. As a Member, I want to be unable to see Managed Certificates I don't own, so that the inventory is only shown to people who need it.
22. As an Organization Administrator, I want to see every Managed Certificate in my Organization, with filters for expiring soon, renewal failing, pending Approval, no Owners, Key Custody, Agent offline and archived, so that I can manage the whole estate.
23. As an Approver, I want to see every Managed Certificate in my Organization, including those pending Approval, so that I can make informed decisions.
24. As a user, I want to see a Managed Certificate's history: all of its Certificates, its name changes, its Approvals, and its Deployment Runs, so that I understand how it got to its current state.

### Creating Managed Certificates and Approval

25. As a Member, I want to propose a new Managed Certificate by submitting a CSR, so that I can get a certificate for an app the platform can't automate while keeping my private key myself.
26. As a Member, I want the platform to reject a CSR whose key algorithm or names don't match the Managed Certificate, so that I find mistakes before anything is issued.
27. As a Member, I want to choose ECDSA P-256 or P-384, or RSA 2048, 3072 or 4096, so that the certificate works with my application.
28. As a Member, I want to request wildcard names, so that one certificate can cover a whole subdomain.
29. As a Member, I want to add Owners (users or Teams) to the Managed Certificate I propose, so that responsibility is clear from the start.
30. As a Member, I want to create a Managed Certificate with no Owners, so that I'm not forced to name a contact I don't have.
31. As an Approver, I want to see a queue of Managed Certificates and name changes waiting for Approval, so that I can work through them.
32. As an Approver, I want to approve or reject the proposed names and give a reason, so that the requester knows the outcome and the decision is audited.
33. As a Member, I want my proposal issued automatically once it's approved, so that I don't have to come back and press another button.
34. As an Organization Administrator, I want Managed Certificates I create or change to skip Approval, so that administrative work isn't held up by a process meant for Members.
35. As an Owner, I want to propose adding or removing names on an existing Managed Certificate, so that it can grow with my application.
36. As an Owner, I want Renewal to keep using the last approved names while my name change waits for Approval, so that a slow Approval never causes an outage.
37. As an Owner of a certificate where I hold the key, I want to upload a new CSR together with my name change, so that the CSR matches the new names once they're approved.

### Issuance and DCV

38. As an Organization Administrator, I want to set up my Organization's own ACME account for Let's Encrypt, choosing production or staging, so that issuance is tied to my Organization and I can test safely.
39. As an Organization Administrator, I want to connect an Infoblox DNS Provider, so that the platform can publish DCV records in our zones.
40. As an Organization Administrator, I want to connect an RFC 2136 DNS Provider (dynamic updates authenticated with a TSIG key), so that BIND, Windows DNS and appliances that support it can be used.
41. As an Organization Administrator, I want to send a DNS Provider's operations through one or more of my Agents, so that DNS inside our network (such as on-prem Infoblox) works with the hosted platform.
42. As an Organization Administrator, I want any online relay Agent to be used when several are assigned, so that one Agent going offline doesn't block issuance.
43. As an Organization Administrator, I want to define a Validation Zone on one of my DNS Providers, so that I can use Delegated DCV without giving the platform write access to my production zones.
44. As an Organization Administrator, I want the platform to show me the exact `_acme-challenge` CNAME record to create for each name that uses Delegated DCV, so that setting it up is simple and correct.
45. As an Organization Administrator, I want to choose, for each DNS name or zone, whether DCV is Direct or Delegated and through which DNS Provider, so that I can mix approaches across my estate.
46. As an Organization Administrator, I want DNS Provider credentials and ACME account keys to be write-only (I can replace or test them but never read them back), so that a compromised account or an impersonated session can't leak them.
47. As an Organization Administrator, I want a "test connection" action for DNS Providers, so that I can check credentials and reachability before issuance depends on them.
48. As a user, I want to see clear error messages when DCV or issuance fails (for example a DNS update rejected, the record not visible, or a rate limit reached), so that I can fix the cause.
49. As an Organization Administrator, I want a warning when an action would probably exceed Let's Encrypt rate limits, so that we don't get locked out by accident.

### Renewal

50. As an Owner, I want to set a Managed Certificate's Renewal Policy to automatic or manual and choose how many days before expiry Renewal happens, so that each certificate fits how it's used.
51. As an Owner of a certificate where I hold the key, I want automatic Renewal to reuse my stored CSR, so that new Certificates are issued without my involvement.
52. As an Owner of a certificate where I hold the key, I want to upload a new CSR at any time, so that I can change my key when I choose.
53. As an Owner, I want to trigger Renewal immediately ("renew now"), so that I can respond to an incident or an urgent change.
54. As an Owner with a manual Renewal Policy, I want to start Renewal myself when I'm ready, so that new Certificates only appear when I can install them.
55. As an Organization Administrator, I want Renewal of an Agent-held key to generate a new key on the Agent every time, so that keys are rotated automatically.
56. As an Organization Administrator, I want failed Renewals retried automatically and shown clearly, so that temporary failures heal and lasting ones get noticed.
57. As an Organization Administrator, I want automatic Renewal to follow the CA's ACME Renewal Information (ARI) window when it is earlier than my Renewal Policy's days-before-expiry, so that we renew promptly when the CA asks (for example before a mass revocation) and benefit from the rate-limit exemption for ARI-coordinated Renewals.
58. As an Organization Administrator, I want a Renewal that's waiting on an offline Agent to be marked "Agent offline" and to resume when the Agent reconnects, so that nothing is lost and the cause is obvious.

### Deployments and Agents

59. As an Organization Administrator, I want to create a single-use Agent Registration token for my Organization, so that I can install and register an Agent securely.
60. As an Organization Administrator, I want to install the Agent as a service on Windows or Linux (amd64 or arm64), so that it runs unattended and survives reboots.
61. As an Organization Administrator, I want Agents to only ever connect outbound to the platform, so that I don't have to open any inbound firewall rules.
62. As an Organization Administrator, I want each Agent to authenticate with its own credential that rotates automatically, so that a stolen registration token can't be reused and Agent credentials don't expire unnoticed.
63. As an Organization Administrator, I want to see every Agent with its host name, OS, version, last contact time and online or offline status, so that I know the state of my automation.
64. As an Organization Administrator, I want Agents running an old version to be flagged, so that I know which ones to upgrade.
65. As an Organization Administrator, I want to revoke an Agent, so that a decommissioned or compromised host can no longer act for my Organization.
66. As an Organization Administrator, I want to upload Bash or PowerShell Deployment Scripts to my Organization's script library, so that I can deploy to any kind of target.
67. As an Organization Administrator, I want every script version to be immutable and identified by its hash, so that the code an Agent runs is exactly what was uploaded and audited.
68. As a Member, Approver or Owner, I want to be unable to upload or edit Deployment Scripts, so that the power to run code on hosts stays with Organization Administrators.
69. As an Organization Administrator, I want to set up a Deployment in one flow (pick the Agent, configure the Managed Certificate with its names and key algorithm, pick the Deployment Script, set the Renewal Policy, deploy), so that automating a certificate takes one guided step.
70. As an Organization Administrator, I want one Agent to serve many Deployments, so that a single host can manage all the certificates it's responsible for.
71. As an Organization Administrator, I want the Agent to receive the key, leaf, chain and full-chain file paths plus the Managed Certificate's identifiers as environment variables, so that my script can place them wherever they're needed, including on other hosts.
72. As an Organization Administrator, I want each Deployment Run's result (exit code, stdout and stderr up to a limit, the Certificate delivered) reported back and recorded, so that I can confirm the deployment worked or diagnose why it didn't.
73. As an Organization Administrator, I want to re-run a Deployment for the current Certificate without renewing, so that I can recover after fixing a broken script or target.
74. As an Organization Administrator, I want the Agent to keep private keys only in a protected local store readable by its service account, so that the keys are as safe on the host as the platform's design assumes.

### Export and download

75. As an Owner, I want to download the current Certificate as PEM, DER or PKCS#7 (P7B), so that I can install it in whatever format my application expects.
76. As an Owner, I want to choose leaf only, leaf plus intermediates, or leaf plus intermediates plus root, so that the bundle matches what my server or client needs.
77. As an Owner, I want to download any earlier Certificate of the Managed Certificate, so that I can roll back or investigate.
78. As a CI pipeline using an API key, I want to fetch the current Certificate of a Managed Certificate in a chosen format and chain option, so that deployment pipelines can pick up renewed certificates on their own.

### Revocation and archive

79. As an Owner or Organization Administrator, I want to revoke a Certificate and give a reason (such as key compromise or superseded), so that a compromised or unwanted certificate stops being trusted.
80. As an Owner or Organization Administrator, I want revocation to happen only when someone explicitly asks for it, so that archiving or changing names never revokes a certificate that's still in use.
81. As an Organization Administrator, I want to archive a Managed Certificate, so that it stops renewing and deploying while its Certificates and history are kept for audit.
82. As an Organization Administrator, I want to see archived Managed Certificates and their history, so that the audit trail survives decommissioning.

### Notifications

83. As an Owner, I want to subscribe users, Teams or channels to a Managed Certificate, so that the right people hear about it.
84. As a Subscriber, I want email notices before expiry, on successful Renewal, on Renewal failure and on Deployment Run failure, so that I can act when something needs me, especially for certificates installed by hand.
85. As an Organization Administrator, I want webhook notification channels, so that notices can go to Microsoft Teams, Slack, ticketing or a SIEM.
86. As a Subscriber who isn't an Owner, I want to receive notices without gaining access to the Managed Certificate in the portal, so that notification doesn't widen access.
87. As an Organization Administrator, I want no one subscribed by default, so that only people who opt in get notices.

### Audit

88. As an Organization Administrator, I want every change to my Organization's state recorded in an append-only audit log with actor, time, action and target, so that I can reconstruct who did what. That includes logins, role changes, Approvals, CSR uploads, issuance, Renewal, revocation, archive, Agent Registration, script uploads, Deployment Runs, setting changes and API key use.
89. As an Organization Administrator, I want to search and filter the audit log, so that I can answer investigation and compliance questions.
90. As an Organization Administrator, I want to stream the audit log to our SIEM (such as CrowdStrike NG-SIEM) by webhook or syslog in a stable JSON schema, so that certificate activity is correlated with the rest of our security telemetry.
91. As an Organization Administrator, I want audit records kept indefinitely, so that our history is never lost.
92. As a Platform Operator, I want a platform-wide setting, off by default, that records impersonation sessions and names the impersonating operator on actions taken during them, so that impersonation can be audited when a customer or regulator requires it.

## Implementation Decisions

### Shape and stack

- The platform is a single deployable web application: a **Bun** runtime, a **Hono** HTTP API, **Better Auth** for identity, **Postgres** as the only datastore, and a **TanStack** front end (Router and Query) styled with **shadcn/ui**. It ships as container images that don't depend on any particular cloud.
- The web UI is a client of the same public HTTP API that API keys and Agents use. There's no private UI-only API. The API contract is described with OpenAPI, generated from the route schemas, and the Agent and its test stub are built against that contract.
- Background work (scheduled Renewals, ACME order progression, notifications, SIEM forwarding) runs in a job queue stored in Postgres, inside the same deployable. There's no separate message broker.
- The **Agent** is a single **Go** binary for Windows and Linux on amd64 and arm64. It runs as a systemd service or a Windows Service. Upgrades in v1 are manual. Agents report their version and the platform flags outdated ones.

### Modules (deep modules with narrow interfaces)

- **Identity and Tenancy.** A wrapper around Better Auth configured with the plugins for organizations (with Teams), SSO (SAML and OIDC, with just-in-time provisioning into the Organization that owns the connection), two-factor, passkey, API key and admin (Platform Operator role with impersonation). Organization roles are **Organization Administrator**, **Approver** and **Member**. Don't use Better Auth's default "owner" role name, because it collides with the domain term **Owner**. Organization login policy (require SSO, require MFA) is enforced here. Other modules ask one question, "can this actor do this action on this resource in this Organization?", and never call Better Auth directly.
- **Managed Certificates.** Owns the lifecycle of a Managed Certificate:
  - its approved names, and at most one pending name change at a time
  - Key Custody (Owner CSR or Agent)
  - key algorithm (ECDSA P-256 or P-384; RSA 2048, 3072 or 4096)
  - Owners (users or Teams, optional), Subscribers and Renewal Policy (automatic or manual, plus days before expiry)
  - Archive state
  - the list of its Certificates, identified by SHA-256 fingerprint

  Rules it enforces:
  - Approval is needed when someone other than an Organization Administrator creates a Managed Certificate or changes its names. It's never needed for Renewal.
  - A CSR's public key algorithm must match, and its names must exactly match the names being issued.
  - Agent Key Custody means exactly one Agent, through exactly one Deployment.
  - Visibility: Organization Administrators and Approvers see everything in the Organization. Members see Managed Certificates they own directly or through a Team.
- **Issuance.** Turns "issue these approved names for this Managed Certificate with this CSR" into a Certificate. It hides the ACME protocol behind a **Certificate Authority** interface whose only v1 implementation is Let's Encrypt (production and staging). Each Organization has its own ACME account(s). It sequences DCV through the DCV module, finalizes with the CSR, stores the chain, and handles revocation with a reason code. The CA interface must support adding more ACME CAs (including ones needing External Account Binding, EAB) and a Private CA later without changes to its callers.
- **DCV.** Given a name and an Organization, it works out whether DCV is Direct or Delegated and through which DNS Provider. It publishes and removes the `_acme-challenge` TXT record, waits until the record is visible, and reports failures with meaningful causes. For Delegated DCV it writes to the Organization's own Validation Zone and can show the CNAME record the Organization must create. There is no platform-wide shared Validation Zone (ADR 0003), and the platform does not try to detect cross-Organization delegation.
- **DNS Providers.** A pluggable interface (present a TXT record, clean it up, test the connection) with Infoblox (WAPI) and RFC 2136 (TSIG) implementations. A DNS Provider runs either directly from the platform or **relayed** through one or more of the Organization's Agents. Any online relay Agent is used, and the same provider code runs on either side.
- **Renewal Scheduler.** Each automatic Managed Certificate becomes due at the **earlier** of two times: the Renewal Policy's number of days before its current Certificate expires, or a time chosen within the CA's ACME Renewal Information (ARI) suggested window. The scheduler polls ARI for current Certificates (respecting the CA's `Retry-After`), and it reacts when the CA moves the window earlier, for example ahead of a revocation event. Renewal orders identify the Certificate they replace, so the CA can treat them as ARI-coordinated. When the CA offers no ARI, only the days-before-expiry rule applies. The scheduler enqueues Renewals and retries failures with backoff. For Agent custody, Renewals wait while the Agent is offline. Its time source is injectable, so tests can control time.
- **Agent Gateway.** The platform side of the Agent protocol:
  - Agent Registration with a single-use token scoped to one Organization
  - an Agent credential made at registration (a bearer secret over TLS, of which the platform keeps only the hash; ADR 0006) and rotated automatically
  - long-poll or polling **work items** (generate a key and CSR, deliver a Certificate and run a Deployment, perform a DNS Provider operation)
  - result reporting, heartbeat, version and online/offline status
- **Deployments and Deployment Scripts.** A script library per Organization. Only Organization Administrators can upload. Script versions are immutable and identified by hash. A **Deployment** binds one Agent, one Managed Certificate with Agent custody, one script version and the Renewal Policy, and it is set up through the guided administrator flow. Every execution produces a **Deployment Run** record: time, Certificate fingerprint, exit code, and output truncated to a limit. The Agent checks the script hash before running it (ADR 0004).
- **Agent (Go).** Generates keys locally using the algorithm on the Managed Certificate, in a store readable only by the service account, and submits CSRs. It never sends a private key to the platform (ADR 0002). It fetches Certificates and runs the Bash or PowerShell script with environment variables pointing to the key, leaf, chain and full-chain files plus the Managed Certificate's identifiers. It reports Deployment Runs and executes relayed DNS Provider operations. It only ever connects outbound over HTTPS, authenticating with its credential. It runs on Linux, Windows and macOS.
- **Export.** Encodes a Certificate as PEM, DER or PKCS#7 (P7B), with leaf only, leaf plus intermediates, or leaf plus intermediates plus root. It never produces PFX or JKS, because the platform holds no keys.
- **Notifications.** Fans events (upcoming expiry, Renewal succeeded or failed, Deployment Run failed, Agent offline, Approval decided) out to a Managed Certificate's Subscribers. v1 channels are email and webhook. There are no default Subscribers.
- **Audit.** An append-only log scoped to each Organization, written in the same transaction as the state change it records. It has a stable JSON event schema, search and filter in the UI, SIEM forwarding by webhook and syslog, and no retention limit. Platform Operator actions are logged on the platform side. **Impersonation is not audited by default:** impersonation sessions starting and ending are not recorded, and actions taken while impersonating are attributed to the impersonated user. A platform-wide setting controlled by the Platform Operator turns on impersonation auditing. When it's on, sessions starting and ending are recorded and actions taken during impersonation also name the impersonating Platform Operator.
- **Secrets.** Stores DNS Provider credentials, ACME account keys and (later) EAB secrets using envelope encryption, with a data key per Organization wrapped by a pluggable KMS (AWS KMS, Azure Key Vault, or a local key for development). Secrets are write-only: they can be replaced or tested, never read back through any API, including by Organization Administrators or impersonating Platform Operators (ADR 0002).

### Key flows

- **Owner CSR (Key Custody: Owner):** a Member proposes names, a key algorithm and a CSR. An Approver approves, unless an Organization Administrator created it. Issuance places an ACME order, DCV runs, and the order is finalized with the CSR. The Certificate is then stored and available for download. Automatic Renewal reuses the stored CSR. A name change needs a new CSR that matches the new names, and it only takes effect when approved.
- **Agent custody:** an Organization Administrator sets up a Deployment, so no Approval is needed. A work item tells the Agent to generate a key and CSR. Issuance runs with that CSR. A work item tells the Agent to fetch the Certificate and run the Deployment Script. The Agent reports a Deployment Run. Every Renewal repeats the whole flow with a **new key**.
- **Pending name change:** the approved names stay in effect for Renewal until the change is approved. A rejected change is discarded and the Managed Certificate is otherwise unaffected.
- **Revocation** is always an explicit action by an Owner or Organization Administrator, with a reason. Archive, name changes and removing a user never revoke.

### Data model highlights

- Every row in the domain tables is scoped to an Organization, and every query is filtered by Organization at the module boundary.
- A Certificate is immutable once stored: fingerprint, serial, validity dates, names, chain, and the CA and ACME account it came from.
- Pending Approval is a state of the Managed Certificate or of its pending name change. It is not a separate "request" entity.
- Archived Managed Certificates and their Certificates, Deployment Runs and audit records are never hard-deleted.

## Testing Decisions

- **What makes a good test:** it acts through a public seam and checks results you can observe from outside:
  - API responses
  - issued Certificates and their contents
  - work items given to Agents
  - Deployment Runs recorded
  - notifications emitted
  - audit events written

  It never asserts on internal tables, private functions or which calls happen in what order. A test should survive a refactor that keeps behavior the same.
- **Seam A: the Platform HTTP API (main seam).** Tests call the Hono application in-process against a real Postgres database, with Better Auth running for real. Only the outside world is replaced:
  - **Pebble**, Let's Encrypt's ACME test server, stands in for the CA. The ACME client is never mocked.
  - Pebble's challenge test server plus an in-memory DNS Provider stand in for DNS, so DCV actually runs.
  - Email and webhook channels are captured, not sent.
  - The clock is injectable, so Renewal timing can be tested.

  Seam A covers:
  - tenancy isolation and roles
  - visibility and Approval
  - Key Custody rules
  - CSR validation
  - Renewal (automatic, manual, retries, Agent offline, ARI windows that move earlier, with Pebble serving ARI)
  - revocation and Archive
  - export formats and chain options
  - notifications to Subscribers
  - audit events
  - write-only secrets
  - Agent Registration
  - the Agent protocol as seen from the platform
- **Seam B: the Agent at its process boundary.** The Go Agent runs against a stub Platform API built from the same OpenAPI contract. Tests check:
  - the key algorithm used, and that no private key appears in any outgoing request
  - that the Deployment Script runs only when its hash matches
  - the environment variables and files the script receives
  - Deployment Run reporting (exit code, output truncation)
  - relayed DNS Provider operations
  - credential rotation
  - offline and retry behavior
- **End-to-end smoke tests (few):** the platform, a real Agent and Pebble together, run through browser automation, cover the headline paths: the administrator's guided Deployment, and Owner CSR proposal → Approval → download.
- **Prior art:** none in this repository yet, since it's a new codebase. Pebble and its challenge test server are the standard harness for ACME clients and should be the model for tests of Issuance and DCV.

## Out of Scope

- Certificate discovery of any kind: network or TLS scanning, Agent host scanning, Certificate Transparency monitoring, cloud API inventory, and importing from DigiCert TLM. This covers **Endpoint**, **Observation**, **Discovered Certificate** and **Adoption**.
- CAs other than Let's Encrypt: other ACME CAs and EAB. The CA interface must allow them later. (Private CAs are specified in `.scratch/private-ca/spec.md`.)
- SCEP and **Enrollment Profiles** for device or client certificates.
- Built-in deployment actions (IIS rebind, Windows certificate store import and so on). Deployment Scripts only.
- Generating or holding private keys on the platform, and PFX or JKS export from the platform.
- More than one Agent for a single Managed Certificate with Agent custody.
- Approver scoping by name pattern (Approvers cover the whole Organization).
- Mapping identity provider groups to Teams or roles, and SCIM.
- Self-service Organization signup.
- Billing, metering and quotas.
- Agent self-update.
- Notification channels beyond email and webhook (Microsoft Teams and Slack are reached through webhooks).
- Enforcing cross-Organization DCV isolation beyond giving each Organization its own accounts, credentials and Validation Zones (ADR 0003).

## Further Notes

- The domain vocabulary is in `CONTEXT.md`, and decisions are recorded in `docs/adr/` (0001 multi-Organization with Better Auth, 0002 the platform never holds private keys, 0003 per-Organization DCV isolation, 0004 admin-uploaded Deployment Scripts). The implementation must use the glossary terms. In particular, say "Deployment", not "automation", and reserve "enrollment" for Enrollment Profiles.
- Accepted risks, each a deliberate decision:
  - Deployment Scripts mean remote code execution on Agent hosts for anyone who compromises an Organization Administrator account or the platform (ADR 0004).
  - Platform Operator impersonation has no consent step and is not audited by default (ADR 0001).
- Let's Encrypt rate limits apply per ACME account. Each Organization has its own accounts, and staging should be the default while an Organization is being set up.
- Decisions settled after the grilling session (confirmed by the user):
  - who may Archive (assumed: Organization Administrators)
  - which events can be notified (listed under Notifications)
  - Approvers can reject with a reason
  - a CSR's names must exactly match the names being issued
  - "renew now" is available to Owners and Organization Administrators
- Choices made while adding the two latest decisions:
  - Automatic Renewal happens at whichever comes first, the ARI window or the days-before-expiry setting.
  - The impersonation-audit setting is platform-wide and controlled by the Platform Operator, rather than set per Organization.
