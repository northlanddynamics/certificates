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
An optional user or Team accountable for a Managed Certificate, who can renew it, change who its Owners are, propose a Name Change, and, if a Member, see it: a Member sees only the Managed Certificates they own (directly or through a Team) or proposed, while Approvers and Organization Administrators see them all. A Managed Certificate may have none. Whoever requests a Managed Certificate through a Certificate Profile becomes one, an Organization Administrator included. Whoever leaves the Organization, or the Team that is deleted, stops being one.
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
A tool in the web app that makes a key pair and a CSR in the user's browser, for an Owner who keeps their own key. The key is made with the browser's WebCrypto (for ML-DSA, where the browser has none, with a pure-JS library loaded only then), never sent to the platform, and offered to the user to download or copy; only the CSR is ever submitted. It stands on its own under Tools in the Organization sidebar, and is the way to make the CSR that Key Custody: Owner asks for.
_Avoid_: key generator, CSR wizard

**Viewer**:
A tool in the web app that reads a CSR or an X.509 certificate, pasted, dropped or chosen as a file (PEM or DER), without being told which, and shows what it holds. For a CSR that is its subject, names, key, signature and requested extensions, and whether the platform would take it, by the rules the server applies; for a certificate, who it is for and from, when it is valid, and its names, key, signature and extensions. A file with several, such as a chain, is shown one at a time. A PKCS#7 (.p7b) bundle is read as the certificates it holds. Under the pasted text it offers the same CSR or certificate in other encodings (PEM, DER, bare base64, and for certificates PKCS#7 as PEM or DER), and, for a chain, all its certificates as one PEM file or PKCS#7 bundle; only the bytes are written another way, so a signature stays valid. It takes no private key, so PKCS#12 and JKS, which carry one, are not offered. It runs in the user's browser and sends nothing, never keeps a private key pasted into it, and does not build chains, so a certificate its issuer signed has its signature left unchecked. It stands under Tools beside the CSR Generator, labelled "PEM Parser" in the sidebar and on its page.
_Avoid_: CSR parser, CSR decoder, certificate decoder

**Approval**:
An Approver's authorization of a Managed Certificate's names; required when a non-administrator creates a Managed Certificate or changes its names, but never for Renewal or for changes made by an Organization Administrator. While a name change is pending Approval, Renewal continues with the last approved names.
_Avoid_: sign-off, authorization

**Proposal**:
A Managed Certificate that someone who may not create one outright has asked for: it waits for Approval with no Certificates and no Issuance, and is either approved, which starts its Issuance, or rejected with a reason, which ends it. Whoever proposed it cannot decide it. One made through a Certificate Profile cannot be approved while that profile is disabled.
_Avoid_: request, draft, pending certificate

**Name Change**:
A Managed Certificate's names replaced by others, together with a CSR for the new names. An Owner proposes one and it waits for Approval, with Renewal continuing on the last approved names and CSR until then; an Organization Administrator's applies at once. Applying one, by approval or by an Organization Administrator, has an Issuance of the new names begin, so it is refused while another Issuance runs. At most one is pending at a time, and a rejected one is discarded, leaving the Managed Certificate as it was. On a Managed Certificate made through a Certificate Profile, a non-administrator's new names must keep to that profile's name rules as they are now, and none is proposed or approved while it is disabled.
_Avoid_: rename, reissue (when meaning the change of names rather than the Issuance that follows)

**Certificate Profile**:
An Organization Administrator's template for Managed Certificates that any member of the Organization may propose against. It fixes the issuer (one ACME CA or one Issuing CA), the key algorithms allowed and, for a Private CA, the validity; it gives the starting Renewal Policy and may name a Team as co-Owner; it is always Key Custody: Owner, and names no Subscribers. It may carry name rules (exact names and zones, how many names, whether wildcards) that a non-administrator's names must keep to; an Organization Administrator is held only to the issuer's own limits, and what they request through it is created outright. Its issuer, key algorithm, validity and Renewal Policy are copied onto the Managed Certificate, which records the profile it came from; its name rules and whether it is enabled are not, so they bear on later Name Changes, and while it is disabled nothing is issued under it: no Proposal is made or approved, no Name Change, no Renewal, until it is enabled again or an Organization Administrator detaches the Managed Certificate from it, which leaves an ordinary Managed Certificate. An Organization may require its non-administrators to propose only through one. Unlike an Enrollment Profile, it makes Managed Certificates, which need Approval and have Owners, and disabling it is not for good.
_Avoid_: template, certificate template, request profile

**Archive**:
Soft deletion of a Managed Certificate by an Organization Administrator, not even its Owners: it stops issuing, renewing and deploying, and discards a name change waiting for Approval, but it and its Certificates and history are retained. Archiving never revokes.
_Avoid_: delete, remove, decommission

**Revocation**:
Telling the Certificate Authority to distrust one Certificate, with an RFC 5280 reason, which an Owner of its Managed Certificate or an Organization Administrator may do, even once it is archived; a Device Certificate is also revoked when its Enrollment Validator's revocation feed asks, and as `superseded` once the replacement a RenewalReq signed with it asked for is issued. The platform records it only once the CA has revoked the Certificate; a CA may confirm later, and until it does the Certificate shows its revocation requested and cannot be revoked again, while a refusal, an unreachable CA or no answer by the deadline leaves it unrevoked, with the cause. Nothing else revokes: not Archive, not a name change, not removing a user. It issues no replacement. A Private CA revokes by putting the Certificate on its Issuing CA's CRL in the same change, and offers two reasons an ACME CA does not take: `affiliationChanged` and `privilegeWithdrawn`.
_Avoid_: cancel, kill, invalidate

**Revocation Request**:
A Revocation asked of a CA that confirms later, such as one reached through an Agent: until the CA answers, nothing is revoked and the Certificate cannot be revoked again; once it confirms, the Revocation is recorded as asked for, and when it refuses, cannot be reached or does not answer by the deadline the request fails with the cause, which shows until it is asked again. A confirmation that comes after the deadline is still recorded.
_Avoid_: pending revocation, revocation job

**Renewal**:
Issuing a new Certificate for a Managed Certificate that already has one, under names that are already approved; whether an Issuance is a Renewal follows from the Managed Certificate having a Certificate, not from who asked. None happens, automatic or asked for, while its Certificate Profile is disabled.
_Avoid_: reissue, re-key (unless the key is specifically being replaced)

**Subscriber**:
A user, Team or notification channel that has opted in to notices about a specific Managed Certificate. There are no default Subscribers.
_Avoid_: watcher, recipient, contact

**Renewal Policy**:
A Managed Certificate's own setting for whether Renewal is automatic or manual and how many days before expiry it happens at the latest, though never before a tenth of the Certificate's life has passed; automatic Renewal happens earlier if the CA's renewal window says so.
_Avoid_: enrollment setting, renewal config

### Issuance

**Issuance**:
One attempt to obtain a Certificate for a Managed Certificate: from an ACME CA it runs DCV and has the CA finalize the order with the CSR, and from a Private CA, with no DCV, the platform has the Issuing CA sign a Certificate for the CSR; either way it ends in a stored Certificate or the recorded cause of its failure. A CA may answer that it will issue later: the Issuance then stays running, pending, until the result arrives or a deadline passes, when it fails as timed out. A Managed Certificate may have many over time, one running at most. Each is of one kind, decided when it begins: its first Issuance (it has no Certificate yet), a Renewal (it has one for its names), or the Issuance of a Name Change (it has one, for other names than it now has).
_Avoid_: order (the ACME protocol's word for part of it), request, job

**Certificate Authority (CA)**:
A pluggable issuer from which the platform obtains Certificates: an ACME CA, which demands DCV, one of the Organization's Private CAs, which does not, or one of its ADCS CAs.
_Avoid_: issuer, provider

**Private CA**:
An Organization's own Certificate Authority, used for internal TLS and device enrollment: a root and one or more Issuing CAs under it, whose keys the platform holds only in a KMS and never sees. A Managed Certificate can be issued from one of its Issuing CAs instead of from an ACME CA, with no DCV; whatever must trust its Certificates needs its root, once for all its Issuing CAs.
_Avoid_: internal CA, enterprise CA

**ADCS CA**:
An Organization's Active Directory Certificate Services CA, which the platform issues from and revokes at, always through Agents assigned to it, and never directly. It holds no key of the platform's and serves no CRL of the platform's. A Managed Certificate or an Enrollment Profile on one names it and one of its Certificate Templates. Only Windows Agents of its Organization can be assigned, each reaching ADCS as its own account; it is added only if one of them reaches it, and named by its config string (`host\CA Name`), which is fixed once it is added.
_Avoid_: Microsoft CA, AD CA, enterprise CA

**Certificate Template**:
An ADCS CA's own template, which decides the validity, key usage and EKUs of what it issues. The platform discovers templates and offers only those it can use: published, enrollable by the Agents' account, and taking the subject from the request.
_Avoid_: profile (a Certificate Profile and an Enrollment Profile are the platform's own), template (unqualified)

**Permitted Name Rules**:
An Issuing CA's exact names and zones (a zone being a name and everything beneath it): the only names it issues for, refused when asked for otherwise. A platform-made Issuing CA carries them as X.509 name constraints, which do not change when the rules later do.
_Avoid_: allowed domains, name policy

**Validity Limits**:
An Issuing CA's maximum and default validity for the TLS Certificates it issues, in days (397 for both unless set). A Managed Certificate on it may choose a validity at or below the maximum, when it is made or with a Name Change, and otherwise gets the default; what is issued is never valid past the maximum or past its Issuing CA's end.
_Avoid_: lifetime policy, max age

**Issuing CA**:
The CA certificate and key that actually sign a Private CA's end-entity Certificates, under a root the platform made or the Organization's own; a Private CA has one or more, each with its own key, Permitted Name Rules, Validity Limits and status. A Managed Certificate is issued from one, and rolling it over means adding another under the same root. It may sign no CA beneath it.
_Avoid_: intermediate, sub-CA

**CRL**:
An Issuing CA's list of the Certificates it signed that are revoked and not yet expired (a platform-made root's, of its Issuing CAs), signed by that CA's key and served to anyone, without credentials and over plain HTTP, from the URL each of its certificates names. It is reissued whenever one is revoked, and at least 3 days before it stops being current, 7 days after it was issued.
_Avoid_: revocation list, blacklist

**ACME CA**:
A Certificate Authority the platform obtains Certificates from over ACME: a directory URL and what is needed to register an account there. Let's Encrypt Staging and Let's Encrypt Production are built in, the same for every Organization, defined in code by stable ids (`letsencrypt-staging`, `letsencrypt-production`) and never changed. An Organization Administrator may add custom ones of the Organization's own, under names unique within it, at an https directory URL that is not a loopback or link-local address; adding one registers the Organization's ACME Account with it in the same step, and nothing is saved if the CA refuses. Its name, tag and contact email may be changed later, but not its directory URL or External Account Binding: for those it is deleted and added again, which only a custom ACME CA no Managed Certificate or Certificate refers to may be. A Managed Certificate whose issuer is an ACME CA names it by id.
_Avoid_: ACME provider, ACME server, environment (for the CA itself)

**Environment Tag**:
A label on an ACME CA, `staging` or `production`, or none, recording what it is for. It changes nothing about how the CA issues: it is shown as a badge and can be filtered on. The built-in ACME CAs carry fixed tags; a past Certificate shows its ACME CA's current tag.
_Avoid_: environment (as a setting that changes behaviour)

**ACME Account**:
An Organization's own account with one ACME CA, at most one per ACME CA. A Managed Certificate on that ACME CA is issued through it. Its key is a Secret.
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

**Deployment Parameter**:
A named value an Organization Administrator gives a Deployment, declared by its Deployment Script version and handed to the script as an environment variable. Plain text, never a Secret.
_Avoid_: binding, argument, variable, setting

**Deployment Run**:
The record of one execution of a Deployment: when it ran, which Certificate it delivered, whether its Deployment Script succeeded, and the script's output.
_Avoid_: job, execution, install log

### Automation

**Agent**:
Software an Organization installs inside its own network that acts for the platform there: generating keys, carrying out Deployments, relaying DNS Provider operations the platform cannot reach directly, and, on a domain-joined Windows host, carrying out an ADCS CA's operations as its own account. Belongs to exactly one Organization and may serve many Deployments.
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

### Device enrollment

**Enrollment Profile**:
A protocol-neutral template under which devices obtain client Certificates in bulk from a Private CA's Issuing CA, without per-certificate Approval or Owners. It fixes its issuer (the Issuing CA), the validity, key usage, EKU and allowed key types of what it issues, and the Enrollment Validator that decides each request; anything a device asks for beyond it is ignored. Devices enroll at its SCEP URL, under an opaque id. Its Issuing CA changes only when an Organization Administrator points it at another, as when the old one is retired, which refuses enrollment until then. A disabled profile refuses every request for good and keeps what it issued; its Device Certificates are pruned a retention period after they end. Not to be confused with a Certificate Profile, which makes Managed Certificates.
_Avoid_: SCEP profile, template

**Enrollment Validator**:
The pluggable integration an Enrollment Profile names, which decides whether an enrollment request may be issued, is told the outcome, and may feed Revocations. It declares whether it vouches for the names in a request; a profile whose validator does not may carry Name Rules that the platform enforces instead, and otherwise issues the names a device asks for, within its Issuing CA's Permitted Name Rules. Its credentials are Secrets. Intune is the first kind; the Shared Challenge kind, which does not vouch for names and is how Iru and network gear enroll, is the next.
_Avoid_: MDM integration (network gear is not an MDM), challenge provider, Iru or Kandji validator (Iru uses the Shared Challenge kind)

**Shared Challenge**:
The one secret every device enrolling under an Enrollment Profile presents, for the Shared Challenge kind of Enrollment Validator, used where the device's manager (such as Iru) can give no per-device challenge. The platform makes it and shows it once; a profile holds at most two, the current one and, while a rotation is under way, the previous one, until an Organization Administrator retires it or it expires. Anyone who holds it can enroll, bounded only by its profile's Name Rules, if it has any, and its Issuing CA's Permitted Name Rules.
_Avoid_: static challenge, PSK, challenge password (the CSR field that carries it)

**Name Rules**:
Optional limits an Organization Administrator may give an Enrollment Profile whose Enrollment Validator does not vouch for names, on what a device puts in its subject and subject alternative names: required subject attributes, allowed SAN types, and wildcard patterns. Anything they do not name is refused. Not to be confused with an Issuing CA's Permitted Name Rules, which still apply on top.
_Avoid_: subject policy, SAN rules

**Device Certificate**:
A Certificate issued under an Enrollment Profile. It belongs to the profile, not to a Managed Certificate, has no Owners, never appears among Managed Certificates, and is renewed by the device enrolling again, or, where its Enrollment Validator allows it, by a SCEP RenewalReq signed with it, which revokes it as superseded once its replacement is issued; neither is a Renewal, which is a Managed Certificate's. It carries the device's ID as its Enrollment Validator knows it (such as Intune's device ID), when the request says. It records the device's key type; one for a weak key (1024-bit RSA, which can be broken, and which an Enrollment Profile allows only when an Organization Administrator chooses it) is marked as such, to be found and replaced.
_Avoid_: client cert, device cert record

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
