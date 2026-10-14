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
An optional user or Team accountable for a Managed Certificate, who can renew it, change who its Owners are, propose a Name Change, and, if a Member, see it: a Member sees only the Managed Certificates they own (directly or through a Team) or proposed, while Approvers and Organization Administrators see them all. A Managed Certificate may have none. Whoever leaves the Organization, or the Team that is deleted, stops being one.
_Avoid_: contact, assignee, requester (when meaning the ongoing responsible party)

**Platform Operator**:
A person who runs the platform itself and creates Organizations; they see inside an Organization only if explicitly invited into it.
_Avoid_: super admin, site admin, admin (unqualified)

**Login Policy**:
What an Organization asks of its users' sign-in, which an Organization Administrator sets. Requiring MFA holds up every member who has a password and no authenticator app (TOTP), in every Organization they belong to and with their API keys, until they set one up; a passkey does not count, because the password still signs in alone. Requiring SSO lets its members sign in only through one of its SSO Connections, not with a password or a passkey; Platform Operators are exempt, so that someone can still get in when an identity provider fails.
_Avoid_: auth policy, security settings

**SSO Connection**:
An identity provider (SAML, such as Ping, or OIDC) that belongs to exactly one Organization and signs in the users of one email domain, which no other connection has and which a DNS TXT record must prove the Organization holds before it signs anyone in. A user signing in through it who is not a member of its Organization becomes a Member, unless they were removed from it; it links to an existing account only of a member of that Organization, never a Platform Operator's.
_Avoid_: SSO provider, IdP (for the connection itself), identity source

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

**CSR Generator**:
A tool in the web app that makes a key pair and a CSR in the user's browser, for an Owner who keeps their own key. The key is made with WebCrypto, never sent to the platform, and offered to the user to download or copy; only the CSR is ever submitted. It stands on its own under Tools in the Organization sidebar, and is the way to make the CSR that Key Custody: Owner asks for.
_Avoid_: key generator, CSR wizard

**Approval**:
An Approver's authorization of a Managed Certificate's names; required when a non-administrator creates a Managed Certificate or changes its names, but never for Renewal or for changes made by an Organization Administrator. While a name change is pending Approval, Renewal continues with the last approved names.
_Avoid_: sign-off, authorization

**Proposal**:
A Managed Certificate that someone who may not create one outright has asked for: it waits for Approval with no Certificates and no Issuance, and is either approved, which starts its Issuance, or rejected with a reason, which ends it. Whoever proposed it cannot decide it.
_Avoid_: request, draft, pending certificate

**Name Change**:
A Managed Certificate's names replaced by others, together with a CSR for the new names. An Owner proposes one and it waits for Approval, with Renewal continuing on the last approved names and CSR until then; an Organization Administrator's applies at once. Applying one, by approval or by an Organization Administrator, has an Issuance of the new names begin, so it is refused while another Issuance runs. At most one is pending at a time, and a rejected one is discarded, leaving the Managed Certificate as it was.
_Avoid_: rename, reissue (when meaning the change of names rather than the Issuance that follows)

**Archive**:
Soft deletion of a Managed Certificate by an Organization Administrator, not even its Owners: it stops issuing, renewing and deploying, and discards a name change waiting for Approval, but it and its Certificates and history are retained. Archiving never revokes.
_Avoid_: delete, remove, decommission

**Revocation**:
Telling the Certificate Authority to distrust one Certificate, with an RFC 5280 reason, which an Owner of its Managed Certificate or an Organization Administrator may do, even once it is archived. The platform records it only once the CA has revoked the Certificate, and nothing else revokes: not Archive, not a name change, not removing a user. It issues no replacement.
_Avoid_: cancel, kill, invalidate

**Renewal**:
Issuing a new Certificate for a Managed Certificate that already has one, under names that are already approved; whether an Issuance is a Renewal follows from the Managed Certificate having a Certificate, not from who asked.
_Avoid_: reissue, re-key (unless the key is specifically being replaced)

**Subscriber**:
A user, Team or notification channel that has opted in to notices about a specific Managed Certificate. There are no default Subscribers.
_Avoid_: watcher, recipient, contact

**Renewal Policy**:
A Managed Certificate's own setting for whether Renewal is automatic or manual and how many days before expiry it happens at the latest, though never before a tenth of the Certificate's life has passed; automatic Renewal happens earlier if the CA's renewal window says so.
_Avoid_: enrollment setting, renewal config

### Issuance

**Issuance**:
One attempt to obtain a Certificate for a Managed Certificate: it runs DCV, has the Certificate Authority finalize the order with the CSR, and ends in a stored Certificate or the recorded cause of its failure. A Managed Certificate may have many over time, one running at most.
_Avoid_: order (the ACME protocol's word for part of it), request, job

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
A pluggable integration with an authoritative DNS service, used to publish the records that satisfy DCV. It runs either directly from the platform or relayed: an Organization Administrator assigns it one or more of the Organization's Agents, and any online one of them carries out its operations beside DNS the platform cannot reach.
_Avoid_: DNS backend, DNS plugin

**Validation Zone**:
A DNS zone belonging to one Organization, reached through that Organization's DNS Provider, into which `_acme-challenge` names are delegated by CNAME, so DCV can be satisfied without write access to the domain's own zone.
_Avoid_: challenge zone, ACME zone

**Delegated DCV**:
DCV performed through a Validation Zone, as opposed to Direct DCV, where the platform writes to the domain's authoritative zone through a DNS Provider. The Organization creates one CNAME per name, from `_acme-challenge.<name>` to `<name>.<Validation Zone>`, which the platform shows it; the platform writes the challenge TXT at the CNAME's target.
_Avoid_: CNAME validation, acme-dns

**DCV Rule**:
An Organization Administrator's choice, for one name or for a zone (the name and everything beneath it), of Direct or Delegated DCV and through which DNS Provider or Validation Zone; a name's own rule beats a zone's, and the longest zone wins. A name under no rule is Direct through whichever DNS Provider publishes it.
_Avoid_: DCV policy, validation setting

**API Key**:
A key for scripts and pipelines, made for one Organization and shown once when made; it can only be revoked. A user's key acts as the user who made it: it carries the permissions they held then, works only for what they may still see and do, and dies with their membership. An Organization's key, which only Organization Administrators make and revoke, belongs to the Organization, sees all its Managed Certificates and outlives whoever made it. Every use is an Audit Event.
_Avoid_: token, service account

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
The one-time binding of a newly installed Agent to an Organization using a single-use token that an Organization Administrator made, which expires if it is not used. The Agent is given its credential.
_Avoid_: enrollment (reserved for Enrollment Profiles), onboarding

**Work Item**:
One thing the platform asks one Agent to do, which the Agent finds by polling and answers with a result, such as carrying out a relayed DNS Provider operation. What an Agent needs in order to do it, such as a DNS Provider's credentials, is added only when the Agent is given it.
_Avoid_: job, task, command

**Agent credential**:
The bearer secret by which an Agent authenticates, made by the platform at Agent Registration and kept by the Agent; the platform keeps only its hash. The Agent replaces it before it ends. Revoking an Agent ends its credential at once.
_Avoid_: agent token (the registration token is used once and is not what an Agent authenticates with), identity certificate (Agents no longer authenticate with certificates)

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
