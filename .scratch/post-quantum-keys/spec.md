# Spec: Post-quantum keys (ML-DSA)

Status: ready-for-agent

## Problem Statement

Every key the platform deals with is RSA or ECDSA, which a large enough quantum computer breaks. An Organization that runs internal TLS on a Private CA cannot today give its servers Certificates whose whole chain resists that: neither its Private CA's root and Issuing CAs nor its Managed Certificates can have a post-quantum key. Some Organizations must also meet CNSA 2.0, which names ML-DSA-87. Public CAs cannot help yet: the CA/Browser Forum has not allowed ML-DSA in publicly trusted TLS certificates, and Let's Encrypt has chosen Merkle Tree Certificates (staging late 2026, production 2027) instead of ML-DSA X.509, so the answer for now is the Organization's own Private CA.

## Solution

ML-DSA (FIPS 204, in X.509 as RFC 9881) becomes a key algorithm the platform supports wherever a Private CA is involved:

- An Organization Administrator can create a Private CA whose root and Issuing CAs have ML-DSA-65 or ML-DSA-87 keys, held in the KMS like any other CA key, in local development as in production.
- A Managed Certificate issued from such a Private CA can have an ML-DSA-44, -65 or -87 key, with either Key Custody: the Owner submits a CSR (pasted, or made by the CSR Generator in the browser), or a Deployment's Agent makes the key and its CSR.
- Where ML-DSA cannot work (an ACME CA, a Private CA of another algorithm, device enrollment) it is refused with a reason before anything waits on it.

## User Stories

1. As an Organization Administrator, I want to create a Private CA with a platform-made root whose keys are ML-DSA-65, so that the Certificates it issues have a quantum-resistant chain.
2. As an Organization Administrator who must meet CNSA 2.0, I want to choose ML-DSA-87 for a Private CA, so that its keys are the strength CNSA 2.0 requires.
3. As an Organization Administrator, I want ML-DSA-44 not offered for a Private CA's keys, so that a CA key, which outlives and outweighs any leaf, is not made at the lowest strength.
4. As an Organization Administrator, I want every Issuing CA I add under an ML-DSA root to have an ML-DSA key of the same algorithm, so that rolling an Issuing CA over never weakens the chain.
5. As an Organization Administrator with my own ML-DSA root, I want to put an ML-DSA Issuing CA under it, so that I can use the platform with a post-quantum root I already run.
6. As an Organization Administrator, I want an Organization root that is not ML-DSA refused for an ML-DSA Issuing CA, so that the chain is never part post-quantum.
7. As an Organization Administrator, I want an ML-DSA Private CA's CRLs signed with ML-DSA and served as any other CRL, so that Revocation works the same way.
8. As an Organization Administrator, I want a Revocation on an ML-DSA Issuing CA to reissue its CRL in the same change, so that nothing about Revocation differs by algorithm.
9. As anyone in the Organization, I want to download an ML-DSA Private CA's root and chain as for any Private CA, so that I can install the root on the clients that must trust it.
10. As an Organization Administrator, I want to be told, when I choose ML-DSA for a Private CA, which clients can verify it (such as OpenSSL 3.5 or later and Chrome 150 or later), so that I do not roll out a root my clients reject.
11. As an Organization Administrator whose platform runs on a KMS without ML-DSA keys, I want ML-DSA refused for a new Private CA with a reason, so that I do not get a CA that cannot sign.
12. As a developer, I want the local KMS to make and sign with ML-DSA keys, so that I can build and test ML-DSA Private CAs without a cloud KMS.
13. As a security reviewer, I want ML-DSA CA keys to be non-exportable KMS keys bound to their Organization like any other CA key, so that ADR 0007 holds for them.
14. As a security reviewer, I want a CRL of any size signable through the KMS, so that a KMS's message size limit never stops a CRL being reissued.
15. As an Owner, I want to create a Managed Certificate on an ML-DSA Private CA with an ML-DSA-44, -65 or -87 key, so that the leaf is quantum-resistant too.
16. As an Owner, I want to choose ML-DSA-44 for a leaf, so that I get the smallest post-quantum signatures and keys when my servers' handshakes are size-sensitive.
17. As an Owner, I want to paste an ML-DSA CSR made with my own tooling (such as OpenSSL 3.5), so that I can keep using the tools I trust.
18. As an Owner, I want an ML-DSA CSR whose key algorithm or names differ from the Managed Certificate's refused with the same reasons as any other CSR, so that ML-DSA behaves like every other key algorithm.
19. As a Member, I want to propose a Managed Certificate with an ML-DSA key on an ML-DSA Private CA, so that Approval works the same for it.
20. As an Owner, I want ML-DSA refused with a reason when the Managed Certificate is on an ACME CA, so that I do not wait for an Issuance the CA will fail.
21. As an Owner, I want ML-DSA refused on a Private CA whose key is RSA or ECDSA, and RSA or ECDSA refused on an ML-DSA Private CA, so that a chain is all post-quantum or not at all.
22. As an Owner, I want the new Managed Certificate dialog to offer only the key algorithms the chosen CA takes, so that I cannot pick one that will be refused.
23. As an Owner, I want to propose a Name Change with an ML-DSA CSR, so that changing names works as for any key.
24. As an Owner, I want to upload a new ML-DSA CSR for Renewal, so that I can re-key with a new ML-DSA key.
25. As an Owner, I want the Managed Certificate's details and its Certificates to show ML-DSA as the key and signature algorithm, so that I can see what I have.
26. As an Organization Administrator, I want to filter the inventory by the ML-DSA key algorithms, so that I can find every post-quantum Managed Certificate.
27. As an Owner who keeps my own key, I want the CSR Generator to make an ML-DSA key and CSR in my browser, so that I need no OpenSSL 3.5 install.
28. As an Owner, I want the CSR Generator to work for ML-DSA even in a browser whose WebCrypto has no ML-DSA, so that I am not limited by my browser.
29. As an Owner, I want the CSR Generator to use the browser's own ML-DSA when it has it, so that the key is made by the browser's native code where possible.
30. As an Owner, I want the ML-DSA private key to stay in my browser and never be sent anywhere, so that ADR 0002 holds for it as for every other key.
31. As an Owner, I want the ML-DSA key offered as a PKCS#8 PEM file that OpenSSL 3.5 reads, so that I can install it on my server.
32. As an Owner, I want no signature hash choice shown for ML-DSA, so that I am not asked a question that does not apply.
33. As an Owner, I want the CSR Generator to show the OpenSSL command that makes the same CSR, so that I can make it on the server where the key will live instead.
34. As a user on a slow connection, I want the ML-DSA code loaded only when I choose an ML-DSA algorithm, so that the CSR Generator stays fast for everyone else.
35. As an Organization Administrator, I want a Deployment's Agent to make an ML-DSA key for a Managed Certificate on an ML-DSA Private CA, so that ML-DSA Certificates are renewed and deployed hands-off.
36. As an Organization Administrator, I want an Agent-made ML-DSA key kept in the Agent's key store like any other, readable only by its service account, so that nothing about key safety differs by algorithm.
37. As an Organization Administrator, I want the Agent to find the ML-DSA key for each Certificate it is given, so that every Deployment Run hands the Deployment Script the right key.
38. As an Organization Administrator, I want Agents already deployed to keep finding their existing RSA and ECDSA keys after the upgrade, so that adding ML-DSA breaks no Deployment.
39. As an Organization Administrator, I want to be warned, when I choose ML-DSA for a Deployment, that whatever the Deployment Script installs into must support ML-DSA, so that I check my web servers and load balancers first.
40. As an Organization Administrator, I want an older Agent asked to make an ML-DSA key to fail the Work Item with a clear reason, so that I know to upgrade it.
41. As an Organization Administrator, I want an Enrollment Profile refused on an ML-DSA Issuing CA, and refused being repointed to one, so that devices are never enrolled under a CA their SCEP clients cannot verify.
42. As an auditor, I want the Audit Events for creating an ML-DSA Private CA or Managed Certificate to record the key algorithm, so that the audit log shows where post-quantum keys are used.
43. As an API user, I want the API to list the ML-DSA key algorithms and say which ones each CA takes, so that my scripts need not hard-code the rules.

## Implementation Decisions

**Algorithms.** Three new key algorithms, `ml-dsa-44`, `ml-dsa-65` and `ml-dsa-87`, alongside the existing five. Pure ML-DSA with an empty context, identified by the RFC 9881 OIDs `2.16.840.1.101.3.4.3.17`, `.18` and `.19`, with the AlgorithmIdentifier's parameters absent, for both keys and signatures. Not HashML-DSA, SLH-DSA, FN-DSA, composite or hybrid signatures, or ML-KEM keys.

**Where each is allowed.**
- A Private CA's key algorithm, which its root and every Issuing CA share as today: `ml-dsa-65` or `ml-dsa-87`; `ml-dsa-44` is refused for CA keys.
- An Organization's own root under an ML-DSA Issuing CA must itself have an ML-DSA key.
- A Managed Certificate's key algorithm: an ML-DSA one only on an ML-DSA Private CA, and only an ML-DSA one there. The rule is all or nothing in a chain: an ML-DSA leaf under an ECDSA CA gains no quantum resistance, and an ECDSA leaf under an ML-DSA CA is still the weak link. The check runs wherever a key algorithm meets a CA: creating or proposing a Managed Certificate, a Name Change and a Renewal CSR. A refusal is a 422 that says why.
- Enrollment Profiles: refused on, and refused being repointed to, an ML-DSA Issuing CA. Device keys stay RSA, and the profile's SCEP RA certificate, signed by its Issuing CA, would carry an ML-DSA signature that SCEP clients (Intune, Iru, network gear) cannot verify.
- ACME Account keys and the SCEP RA key: unchanged.

**What the API says.** The list of CAs a Managed Certificate can be issued from says which key algorithms each takes, and the web offers only those; the web holds no copy of the rule. Audit Events that already record a key algorithm record the ML-DSA ones the same way.

**X.509 library.** The server and the web app move to version 2 of the X.509 library: the version pinned today cannot verify an ML-DSA signature, and 2.2.0 can (checked with a prototype). Version 2 needs a reflection polyfill loaded before it. Bun 1.4.2 generates, signs and verifies ML-DSA natively in both its Node crypto and WebCrypto, and reports an ML-DSA public key's type as `ml-dsa-44/65/87`.

**KMS seam (amends ADR 0007, in a new ADR).** The seam today signs a digest made with one hash per algorithm; pure ML-DSA signs the whole message, and a KMS limits message size (AWS KMS to 4 KB, smaller than a large CRL). For ML-DSA keys the seam instead signs the *external μ*, the 64-byte message representative the platform computes, after which the signature is an ordinary pure ML-DSA signature over the whole message. From the prototype:

```
tr = SHAKE256(publicKey, 64 bytes)
μ  = SHAKE256(tr ‖ 0x00 ‖ 0x00 ‖ message, 64 bytes)   // pure ML-DSA, empty context
```

- **Creating keys.** The seam creates ML-DSA-65 and ML-DSA-87 keys like the others.
- **Signing.** It signs μ for ML-DSA keys and a digest for the rest.
- **Signature format.** An ML-DSA signature is returned raw, as X.509 carries it, so there is no DER conversion.
- **Local KMS.** It makes the key with Bun's native ML-DSA and wraps it under its master key, bound to its algorithm and Organization like every other key; Bun exports the key as the 32-byte seed form. It signs μ with `@noble/post-quantum`'s internal signing with external μ, from that seed, because Node crypto signs only a whole message. A prototype's μ signature over a 100 KB message verified with Bun's native verify.
- **Production KMSes.** AWS KMS takes μ as `MessageType: EXTERNAL_MU` (to be confirmed against AWS's documentation). Google Cloud KMS's support for signing μ is to be checked. Azure Key Vault has no ML-DSA keys, so ML-DSA is refused for a Private CA where it is the KMS. The new ADR records all of this.

**Private key files.** Wherever the platform's code produces an ML-DSA private key file (the CSR Generator's download, the Agent's key store) it is unencrypted PKCS#8 PEM in the RFC 9881 seed form: a PrivateKeyInfo whose privateKey is `[0] IMPLICIT OCTET STRING` holding the 32-byte seed. Bun and OpenSSL 3.5 read it.

**Agent.** Go's standard X.509 package cannot make an ML-DSA CSR, encode an ML-DSA key, or give an ML-DSA Certificate's public key. Instead:

- **Signing.** The Agent signs with Cloudflare's CIRCL ML-DSA package; its current version needs Go 1.25, the version the Agent already names. When the Agent moves to Go 1.26 or later, the standard library's ML-DSA package may replace CIRCL.
- **The CSR.** The Agent builds the PKCS#10 itself with Go's ASN.1 encoder, and that stays even with the standard library's ML-DSA. The CSR holds:
  - the subject (the first name as CN);
  - a SubjectPublicKeyInfo holding the raw public key;
  - the extensionRequest attribute, as a SET holding a SEQUENCE of Extensions, which carries the SAN. A prototype that left out the inner SEQUENCE was accepted by the server's library but rejected by Go's parser, with the SAN lost.
- **Signature.** It is randomized pure ML-DSA with an empty context.
- **Finding the key.** The key store names a key by the hash of the Certificate's raw SubjectPublicKeyInfo instead of re-encoding its parsed public key, which Go leaves empty for ML-DSA. For RSA and ECDSA this is the same name as before, because the CA copies the CSR's SubjectPublicKeyInfo into the Certificate unchanged.
- **Contract.** The Agent contract and the `deployment.generate_key` payload gain the three algorithms. An Agent that does not know one fails the Work Item with a reason, as it does today for an algorithm it does not make.
- **Prototype.** A prototype CSR built this way was verified by the server's X.509 library 2.2.0 and parsed, SAN included, by Go's own CSR parser.

**CSR Generator.**
- **Making the key.** Where the browser's WebCrypto can make an ML-DSA key (detected by trying to), the Generator uses it. Otherwise it uses `@noble/post-quantum`, a pure-JS ML-DSA, loaded only once an ML-DSA algorithm is chosen.
- **Building the CSR.** Without native support, the CSR is built from the ASN.1 CSR and X.509 schema packages the X.509 library already depends on, in the same shape as the Agent's. A prototype of this path produced a CSR the server's library 2.2.0 verified.
- **Key file.** The key is offered as the seed-form PKCS#8 file in both paths.
- **Signature options.** The signature hash choice hides for ML-DSA.
- **OpenSSL command.** The Generator shows the equivalent OpenSSL 3.5 command for the chosen names, such as `openssl req -new -newkey ml-dsa-65 -nodes -keyout key.pem -out req.csr -subj "/CN=…" -addext "subjectAltName=DNS:…"`.
- **Key safety.** The key never leaves the browser, so ADR 0002 holds.
- **Glossary.** The glossary's CSR Generator entry stops saying the key is always made with WebCrypto.

**Deployments.** Whatever a Deployment Script installs an ML-DSA key and Certificate into must itself support ML-DSA (OpenSSL 3.5 or later underneath, for example). The platform cannot make up for that and says so where ML-DSA is chosen for a Deployment.

**Schema.** No new columns. Key algorithms are stored as text and checked against the code's list, which gains the three values.

## Testing Decisions

A good test checks what an outside party sees: the API's answers, the Certificates, CSRs and CRLs it hands out (verified with an independent library), and what an Agent does at its process boundary. It does not reach into how a module computes them. All tests go through the four seams that exist today; no new seam is added.

- **Seam A (the Hono app in-process, real Postgres, local KMS)** carries the bulk, following the existing Private CA, CRL, organization-root, rollover and Managed Certificate tests. It covers:
  - creating an ML-DSA-65 and an ML-DSA-87 Private CA, and refusing ML-DSA-44 for a CA;
  - issuing an ML-DSA Managed Certificate from a pasted CSR, and verifying its chain to the root with the X.509 library;
  - Revocation reissuing an ML-DSA-signed CRL that verifies;
  - adding an Issuing CA under an ML-DSA root;
  - an Organization root of the wrong algorithm being refused;
  - each refusal in "Where each is allowed": an ACME CA, an RSA or ECDSA Private CA, an Enrollment Profile on or repointed to an ML-DSA Issuing CA, each a 422;
  - a Name Change and a Renewal with ML-DSA CSRs;
  - the CA list reporting the key algorithms each CA takes;
  - Audit Events recording the key algorithm.
- **The KMS signing contract** that every KMS keeps gains the ML-DSA algorithms. A key is created, its public key read, μ signed, and the signature verified as pure ML-DSA over the whole message with WebCrypto, including a message over 4 KB. It also checks that a key is refused under another Organization's context. The local KMS runs it now; an AWS or Google implementation runs it unchanged later.
- **The CSR Generator module through the real CSR parser**, as its existing test does for the five algorithms today. It generates a CSR for each ML-DSA algorithm on both the noble path and the native path (the test runtime has native ML-DSA, so the noble path is forced), and checks that the parser accepts it with the right algorithm and names and that the key file re-imports from its seed.
- **Seam B (the Go Agent against a stub of the platform built from its contract)**, as the existing Deployment tests do. For each ML-DSA algorithm:
  - a `deployment.generate_key` Work Item yields a CSR that Go's parser reads with its names;
  - the stored key re-imports from its seed, and a Deployment Run hands the Deployment Script that key for an ML-DSA Certificate;
  - existing RSA and ECDSA keys keep their file names.

  A CSR the real Agent made is also kept as a fixture that the server's CSR parser accepts, so the two ends stay in step.

## Out of Scope

- ML-DSA for publicly trusted certificates, and Merkle Tree Certificates; revisit when Let's Encrypt's ACME extension is published.
- ML-DSA Device Certificates, and SCEP with ML-DSA.
- Composite or hybrid (ML-DSA with ECDSA) certificates, SLH-DSA, FN-DSA, HashML-DSA, ML-KEM keys.
- An AWS, Google or Azure KMS implementation; only the local KMS exists today, and this spec adds ML-DSA to the seam and to it.
- Mixing algorithms within one chain, or a Private CA whose Issuing CAs differ in algorithm.
- Changing a Managed Certificate's key algorithm between RSA/ECDSA and ML-DSA, which would mean moving it to another CA.
- Passphrase-encrypted key files.

## Further Notes

- Size: an ML-DSA-65 CSR is about 5.3 KB (ML-DSA-65 public key 1,952 bytes, signature 3,309), well within the platform's CSR size limit; a three-certificate ML-DSA-65 chain adds roughly 15 KB to a TLS handshake. That is a reason an Owner may prefer ML-DSA-44 for leaves.
- Before shipping the CSR Generator's fallback, check whether `@noble/post-quantum` (prototyped at 0.7.1) has been independently audited, and record it.
- Client support to point users at: OpenSSL 3.5 or later; Chrome 150 or later for ML-DSA roots in private PKI; Windows AD CS gained ML-DSA in its May 2026 update, with TLS still limited. Firefox and Safari do not yet verify ML-DSA certificates.
- The CA/Browser Forum's ML-DSA ballot was still in drafting in its August 2026 minutes; if it passes, ML-DSA on an ACME CA becomes a question of which CAs offer it.
- Implementation order is in `issues/`: the X.509 library upgrade, the KMS seam and its ADR, a tracer from ML-DSA Private CA to ML-DSA Managed Certificate, then six tickets that can run in parallel.
