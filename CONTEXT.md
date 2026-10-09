# Certificate Management

A multi-organization platform for inventorying, issuing, renewing and deploying TLS certificates, built primarily on ACME (Let's Encrypt first), to replace manual certificate handling and DigiCert Trust Lifecycle Manager.

## Language

### Tenancy and ownership

**Organization**:
An isolated tenant of the platform with its own users, teams, certificates and integrations.
_Avoid_: tenant, account, company

**Team**:
A named group of users within an Organization.
_Avoid_: group, department

**Owner**:
An optional user or Team accountable for a Managed Certificate, who can renew it. A Managed Certificate may have none.
_Avoid_: contact, assignee, requester (when meaning the ongoing responsible party)

**Platform Operator**:
A person who runs the platform itself and creates Organizations; they see inside an Organization only if explicitly invited into it.
_Avoid_: super admin, site admin, admin (unqualified)

**Organization Administrator**:
An Organization role with full control of that Organization, including Deployments, Deployment Scripts and integrations; changes they make need no Approval.
_Avoid_: admin (unqualified), org owner

**Approver**:
An Organization role permitted to grant Approval, distinct from Organization administration.
_Avoid_: admin (when meaning the person who approves), reviewer

### Certificates

**Managed Certificate**:
The long-lived, configurable unit the platform manages: its names, key settings, Owners and renewal and deployment policy. Its names may change over time.
_Avoid_: certificate (when meaning the configured thing), cert record, order

**Certificate**:
One immutable issued X.509 certificate, identified by its fingerprint; a Managed Certificate accumulates many over time.
_Avoid_: cert version, instance

**Key Custody**:
Where a Managed Certificate's private key is generated and held: by the Owner, who submits a CSR, or by exactly one Agent. The platform never holds private keys.
_Avoid_: key mode, key ownership

**Approval**:
An Approver's authorization of a Managed Certificate's names; required when a non-administrator creates a Managed Certificate or changes its names, but never for Renewal or for changes made by an Organization Administrator. While a name change is pending Approval, Renewal continues with the last approved names.
_Avoid_: sign-off, authorization

**Archive**:
Soft deletion of a Managed Certificate: it stops renewing and deploying, but it and its Certificates and history are retained. Archiving never revokes.
_Avoid_: delete, remove, decommission

**Renewal**:
Issuing a new Certificate for a Managed Certificate whose names are already approved.
_Avoid_: reissue, re-key (unless the key is specifically being replaced)

**Subscriber**:
A user, Team or notification channel that has opted in to notices about a specific Managed Certificate. There are no default Subscribers.
_Avoid_: watcher, recipient, contact

**Renewal Policy**:
A Managed Certificate's own setting for whether Renewal is automatic or manual and how many days before expiry it happens at the latest; automatic Renewal happens earlier if the CA's renewal window says so.
_Avoid_: enrollment setting, renewal config

### Issuance

**Certificate Authority (CA)**:
A pluggable issuer from which the platform obtains Certificates, such as an ACME CA.
_Avoid_: issuer, provider

**ACME Account**:
An Organization's own account with a Certificate Authority, in its staging or production environment. Its key is a Secret.
_Avoid_: CA account, registration

**Domain Control Validation (DCV)**:
Proof, demanded by a Certificate Authority, that the requester controls a domain name before a certificate naming it is issued.
_Avoid_: domain verification, challenge (when meaning the whole process)

**DNS Provider**:
A pluggable integration with an authoritative DNS service, used to publish the records that satisfy DCV.
_Avoid_: DNS backend, DNS plugin

**Validation Zone**:
A DNS zone belonging to one Organization, reached through that Organization's DNS Provider, into which `_acme-challenge` names are delegated by CNAME, so DCV can be satisfied without write access to the domain's own zone.
_Avoid_: challenge zone, ACME zone

**Delegated DCV**:
DCV performed through a Validation Zone, as opposed to Direct DCV, where the platform writes to the domain's authoritative zone through a DNS Provider.
_Avoid_: CNAME validation, acme-dns

**Secret**:
A value the platform must hold, such as an ACME Account's key or a DNS Provider's credentials, that can be replaced or tested but never read back by anyone, including Organization Administrators and impersonating Platform Operators.
_Avoid_: credential (when meaning the stored value), password

### Deployment

**Deployment**:
An Organization Administrator's arrangement for one Agent to generate the key for a Managed Certificate, obtain its Certificates on its Renewal Policy and put them into use by running a Deployment Script.
_Avoid_: automation, install, target, binding

**Deployment Script**:
A Bash or PowerShell script, uploaded only by Organization Administrators, that an Agent runs to place a newly obtained key and Certificate wherever it is needed, including on other hosts.
_Avoid_: hook, post-install command, action

**Deployment Run**:
The record of one execution of a Deployment: when it ran, which Certificate it delivered, whether its Deployment Script succeeded, and the script's output.
_Avoid_: job, execution, install log

### Automation

**Agent**:
Software an Organization installs inside its own network that acts for the platform there: generating keys, carrying out Deployments and relaying DNS Provider operations the platform cannot reach directly. Belongs to exactly one Organization and may serve many Deployments.
_Avoid_: client, daemon, connector, relay

**Agent Registration**:
The one-time binding of a newly installed Agent to an Organization using a single-use token.
_Avoid_: enrollment (reserved for Enrollment Profiles), onboarding

### Audit

**Audit Event**:
One record in an Organization's append-only audit log: who did what to which target, and when. Written together with the change it records, so a change that does not happen leaves none.
_Avoid_: audit entry, audit record, log line

### Device certificates (future)

**Private CA**:
A Certificate Authority operated for an Organization's internal use rather than public trust.
_Avoid_: internal CA, enterprise CA

**Enrollment Profile**:
A template under which devices obtain client Certificates in bulk from a Private CA, without per-certificate Approval or Owners.
_Avoid_: SCEP profile, template

### Discovery (future)

**Endpoint**:
A place a Certificate is served or stored, such as a `host:port`, an IIS binding, a load-balancer profile or a key vault entry.
_Avoid_: target, location, install

**Observation**:
A record that a specific Certificate was seen on a specific Endpoint at a specific time.
_Avoid_: scan result, sighting

**Discovered Certificate**:
A Certificate that belongs to no Managed Certificate, known only because it was observed.
_Avoid_: unmanaged cert, found cert, rogue cert

**Adoption**:
Bringing a Discovered Certificate under management by creating a Managed Certificate from it.
_Avoid_: import, claim
