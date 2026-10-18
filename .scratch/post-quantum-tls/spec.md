# Spec: Post-quantum TLS, the "support now" items

Status: ready-for-agent

Research: `docs/research/post-quantum-tls.md` (§6 "Support now"). This spec covers only those items; ML-DSA for Private CAs, Merkle Tree Certificates and everything else in "Behind a flag" and "Watch" are out of scope.

## Problem Statement

Customers and their auditors are asking what the platform does about quantum computers. The UK NCSC wants a discovery exercise by 2028, the EU wants work started by the end of 2026, and NIST's draft guidance would deprecate RSA and ECC after 2030. The answer has two halves.

- **Key exchange** is the urgent half, because traffic recorded today can be decrypted later ("harvest now, decrypt later"). The hybrid group `X25519MLKEM768` (RFC 10024) fixes it, and the TLS endpoints negotiate it without involving the certificate. The platform's Bun runtime and the Go Agent already negotiate it by default, but nothing says so and nothing stops a runtime upgrade, a config change or a `GODEBUG` setting from quietly turning it off. Platform Operators don't know what their TLS terminator has to support. Organization Administrators don't know that the servers their Deployment Scripts configure are where post-quantum key exchange is switched on, and that getting a new certificate from the platform does nothing for it.
- **Certificate keys** stay classical. The Baseline Requirements allow only RSA and ECDSA for publicly trusted certificates, so an ACME CA can't issue for a post-quantum key. Today an Owner who pastes a CSR with an ML-DSA key gets "the CSR's signature does not verify against its own public key". That is wrong and sends them looking for a broken key, when the real answer is that post-quantum keys aren't supported yet.

## Solution

- **The platform's own TLS is pinned to post-quantum key exchange.** A test fails if any of these stops negotiating `X25519MLKEM768`:
  - the platform's TLS listener, when it serves TLS itself;
  - its outbound connections (ACME CAs, DNS Providers, Intune, the audit SIEM transport);
  - the Agent's connection to the platform.
- **Platform Operators are told what to require of a TLS terminator.** If something other than the platform terminates TLS, it should offer `X25519MLKEM768`, for example nginx or HAProxy built with OpenSSL ≥ 3.5, or a cloud load balancer with a post-quantum TLS policy. Otherwise the Agent channel and the web UI lose post-quantum key exchange at the terminator.
- **Organization Administrators are told where post-quantum key exchange is switched on.** The Deployment Scripts page says it is a setting of the server a script configures, not of the certificate, and that a server built with OpenSSL ≥ 3.5 offers it by default.
- **A post-quantum key in a CSR is refused with a message that says so.** The message names the key and the key algorithms the platform accepts. Classical key algorithms are unchanged.
- **Discovery is prepared.** The glossary's Observation records the TLS protocol version and the key exchange group used, so that the future Discovery feature has "Endpoints without post-quantum key exchange" from the start.

## User Stories

1. As a Platform Operator, I want the platform's TLS listener to negotiate `X25519MLKEM768` with clients that offer it, so that traffic to the platform recorded today can't be decrypted by a future quantum computer.
2. As a Platform Operator, I want the platform's connections to ACME CAs, DNS Providers, Intune and the SIEM to negotiate `X25519MLKEM768` where the peer supports it, so that DNS Provider credentials and audit events in transit are protected the same way.
3. As a Platform Operator, I want a test to fail if a Bun upgrade or a TLS config change drops post-quantum key exchange, so that we never lose it without noticing.
4. As a Platform Operator, I want the platform to still connect to peers that offer only classical groups, so that turning on post-quantum key exchange breaks no integration.
5. As a Platform Operator, I want the README to say what a TLS terminator in front of the platform must offer, so that I don't lose post-quantum key exchange at the load balancer.
6. As a Platform Operator, I want the README to say that post-quantum key exchange needs TLS 1.3, so that a terminator left on TLS 1.2 is recognised as not protected.
7. As an Organization Administrator, I want my Agents' connections to the platform to use `X25519MLKEM768`, so that the Agent credential and the Certificates it collects are protected in transit.
8. As an Organization Administrator, I want a test to fail if the Agent stops offering `X25519MLKEM768`, so that a Go upgrade or a TLS config change can't quietly drop it.
9. As an Organization Administrator, I want the Agent to still reach a platform or Infoblox appliance that offers only classical groups, so that nothing breaks behind an older terminator.
10. As an Organization Administrator, I want the Deployment Scripts page to tell me that post-quantum key exchange is a setting of the server my script configures, so that I know a new certificate alone won't give it to me.
11. As an Organization Administrator, I want to be told that a server built with OpenSSL ≥ 3.5 offers it by default, and that older servers need an explicit group list or an upgrade, so that I know what to check on my hosts.
12. As an Owner, I want a CSR with a post-quantum key (ML-DSA, SLH-DSA or ML-KEM) refused with a message naming the key and the algorithms the platform accepts, so that I don't hunt for a broken key.
13. As an Owner, I want that message the same wherever I submit a CSR (creating a Managed Certificate, proposing a Name Change, uploading a CSR for Renewal), so that I learn the rule once.
14. As an Owner using the CSR Generator, I want it to keep offering only ECDSA and RSA, so that I can't make a key no CA will issue for.
15. As an Owner, I want my existing ECDSA and RSA CSRs accepted exactly as before, so that this change costs me nothing.
16. As an Approver, I want Managed Certificates' key algorithms unchanged, so that nothing new needs my Approval.
17. As an auditor reading the platform's documentation, I want to see which post-quantum protections are in place and which are still to come, so that I can answer the organization's post-quantum questionnaire.
18. As a future Discovery user, I want each Observation to record the TLS protocol version and the key exchange group the Endpoint used, so that I can list Endpoints without post-quantum key exchange.
19. As a future Discovery user, I want Endpoints that offer only TLS 1.2 shown as lacking post-quantum key exchange, so that I see them as part of the migration.
20. As a developer, I want the platform's post-quantum key exchange tests to run in CI with the tools CI already installs, so that they guard every change.
21. As a developer, I want the tests to name the group a connection actually used, not only pass or fail, so that a failure says what was used instead.

## Implementation Decisions

**Post-quantum key exchange is confirmed, not built.** No TLS configuration is added to the platform or the Agent. Both rely on their runtime's defaults, which already prefer `X25519MLKEM768` (Bun 1.4.2; Go ≥ 1.24, and from Go 1.26 also `SecP256r1MLKEM768` and `SecP384r1MLKEM1024`). Setting an explicit group list would freeze the list and miss later defaults. If a test shows a path that doesn't offer the group, the fix is the smallest config change on that path, and the spec's tests then pin it.

**The paths that are pinned.**
- The platform's TLS listener: the `Bun.serve` options the server entry point builds from `TLS_CERT_FILE` and `TLS_KEY_FILE`. Building those options moves into a small exported function, so the test serves with exactly what production serves with, rather than a copy.
- The platform's outbound `fetch`, which the ACME client, the Infoblox DNS Provider and the Intune Enrollment Validator use.
- The platform's outbound `node:tls` connection, which the audit SIEM transport uses.
- The Agent's platform client.
- The Agent's Infoblox relay client: it shares Go's defaults, so pinning the platform client covers it, unless its TLS config diverges from the platform client's.

**Bun can't report the group, so a Go peer reports it.** `getEphemeralKeyInfo()` returns `{}` under Bun 1.4.2, for client and server sockets alike. So the server's test runs a small Go TLS peer, a test-support program, with `go run`. CI installs Go (from `agent/go.mod`) before `bun run test`. The peer has two modes:
- **server:** it serves TLS on a port with a throwaway certificate and reports the version, group and cipher of each connection as a line of JSON;
- **client:** it connects to a given port, offering only a given group list, and reports the same.

A test that needs the peer is skipped with a clear reason when `go` isn't on the PATH, so a developer without Go isn't blocked. CI always has Go, so it never skips there.

**The Agent's side uses Seam B.** The platformstub records each TLS connection's negotiated group (from its `tls.Config`'s connection state hook) and exposes the last one. The Agent's tests assert it is `X25519MLKEM768`. The stub's own TLS config isn't changed, so it stands for a platform on Go's defaults. A stub option that restricts the server to classical groups lets one test show that the Agent still connects.

**Classical fallback is part of the contract.** Every pinned path also has a case where the peer offers only `X25519` (and for the listener, a client offering only `P-256`), and the connection succeeds.

**CSR key algorithm before signature.** The CSR parser reads the key's algorithm before it verifies the signature. A key that `createPublicKey` reports as `ml-dsa-*`, `slh-dsa-*` or `ml-kem-*` is refused with a `CsrError` like: "the CSR's key is ML-DSA-65, a post-quantum algorithm the platform does not issue for yet; only ECDSA (P-256, P-384) and RSA (2048, 3072, 4096) are supported". The supported key algorithms (`ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-3072`, `rsa-4096`) don't change, so the API's key algorithm enum, the database and the web pickers don't change either. Device CSRs over SCEP are already RSA-only, and their message doesn't change.

**Documentation.**
- **README:** a "Post-quantum TLS" section for Platform Operators covering:
  - the platform's listener and outbound connections negotiate `X25519MLKEM768` by default;
  - a terminator in front of the platform must offer it, and needs TLS 1.3 to do so;
  - examples of terminators that do (OpenSSL ≥ 3.5 builds of nginx, HAProxy or Apache; Caddy 2.10+; Traefik 3.4.2+);
  - certificates stay RSA and ECDSA until the CA/Browser Forum allows otherwise, and the research doc has the rest.
- **Deployment Scripts page:** one sentence in the page's description, in the web's existing muted-text style: post-quantum key exchange is a setting of the TLS server a script configures, on by default with OpenSSL ≥ 3.5, and the platform's certificates work with it unchanged. No link, since the web links to no docs today.

**Glossary.** In `CONTEXT.md`, under Discovery (future), the Observation definition gains: it also records the TLS protocol version and the key exchange group the Endpoint negotiated, when the Endpoint is a TLS listener. Nothing is built for Discovery.

## Testing Decisions

**What makes a good test here.** Assert what a peer on the wire sees, never a config object. A test that the listener options contain no group list proves nothing about what Bun negotiates; a Go client that reports `X25519MLKEM768` does. Each assertion names the group that was negotiated, so a failure reads like "negotiated X25519, wanted X25519MLKEM768".

**Server tests** (one new test file, using the Go peer):
- The listener, built by the same function the entry point uses, with a test certificate, has to:
  - negotiate `X25519MLKEM768` and TLS 1.3 with a Go client on its defaults;
  - negotiate `X25519` with a client offering only `X25519`;
  - negotiate `P-256` with a client offering only `P-256`.
- `fetch` to a Go server negotiates `X25519MLKEM768`, and still succeeds against a server offering only `X25519`.
- `node:tls` `connect` with the audit transport's options does the same. Prior art: `server/test/audit-transport.test.ts` already stands up TLS servers for the SIEM transport.
- Prior art for spawning a helper process from a server test: `server/test/scep-interop.test.ts`, which runs micromdm's SCEP client.

**CSR tests:**
- An ML-DSA-65 CSR is refused with the post-quantum message through the real CSR parser.
- The same CSR is refused with the same message through the Managed Certificate create route. One route is enough, because all three share the parser.
- The fixture is a checked-in PEM generated with OpenSSL ≥ 3.5 or Go ≥ 1.27, with a comment saying how it was made, since neither is in CI.
- The existing ECDSA and RSA CSR tests stay green. Prior art: `server/test/managed-certificates.test.ts` and `server/test/csr-generator.test.ts` (which round-trips CSRs through `parseCsr`).

**Agent tests (Seam B):**
- With the platformstub on its defaults, registration and a poll negotiate `X25519MLKEM768`.
- With the stub limited to classical groups, the Agent still registers.
- Prior art: `agent/internal/platformstub/stub_test.go` and the Agent's Seam B tests.

**Not tested:** the README and the Deployment Scripts page sentence, which are copy, and the glossary.

## Out of Scope

- Everything outside the research's "Support now" tier:
  - ML-DSA for Private CAs, and the upgrades it needs: `@peculiar/x509` 2.x, a μ-based `Kms` path, Go 1.27 in the Agent;
  - Merkle Tree Certificates over ACME;
  - public ML-DSA certificates, composite signatures, SLH-DSA, FN-DSA and ML-KEM certificates;
  - post-quantum device keys over SCEP.
- Building Discovery, Endpoints or Observations. Only the glossary changes.
- Configuring an explicit TLS group list on the platform or the Agent.
- Choosing or configuring a production TLS terminator. The platform either serves TLS itself or sits behind one that isn't its concern (ADR 0006). The README states the requirement only.
- Checking or changing the TLS that Deployment Scripts configure on customer hosts.
- Raising the Agent's minimum TLS version from 1.2 to 1.3.

## Further Notes

- The research found no Bun API that exposes the negotiated group, and this spec confirmed it (`getEphemeralKeyInfo()` returns `{}`). If Bun adds one, the server tests can drop the Go peer for the outbound cases. The listener case still needs an external client.
- DigiCert's migration guidance agrees with this split: hybrid `X25519MLKEM768` for key exchange now with no certificate change, pure ML-DSA rather than composite for certificates later, and post-quantum key exchange only in TLS 1.3.
- When ML-DSA for Private CAs is specced, the post-quantum CSR refusal becomes the place that, behind its flag, accepts ML-DSA for Private CA issuers and refuses it for ACME CAs.
