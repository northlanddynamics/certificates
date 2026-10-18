# Research: post-quantum algorithms and key types for TLS

Which post-quantum (PQ) key exchange groups and certificate key types the platform should support, and where in the code each would land. Researched 2026-10-18.

## Sources and how far to trust them

From this environment `iana.org`, `datatracker.ietf.org`, `rfc-editor.org`, `csrc.nist.gov`/`nvlpubs.nist.gov`, `nsa.gov`, `ncsc.gov.uk`, `learn.microsoft.com`, `blog.cloudflare.com`, `security.googleblog.com`, `chromestatus.com` and `go.dev` are all unreachable. GitHub (git and raw), `nodejs.org`, `developer.apple.com`, `proxy.golang.org` and the npm registry are reachable. Where the owner publishes its text on GitHub (IETF draft repos, the CA/B Forum, Chrome's root program, Let's Encrypt's site, Cloudflare's docs) I read it there. Everything else is a search excerpt, and the table says so.

| Tag | Source | Status |
|---|---|---|
| **[ECDHE-MLKEM]** | [`post-quantum-cryptography/draft-kwiatkowski-tls-ecdhe-mlkem`](https://github.com/post-quantum-cryptography/draft-kwiatkowski-tls-ecdhe-mlkem) `9da5493` (2026-08-19), `draft-ietf-tls-ecdhe-mlkem.md`. Its log has "Sync with RFC Editor's version of 2026-07-29", and the text calls itself RFC 10024. | Read. **Primary**, but it is the authors' copy of the RFC, not the RFC Editor's. |
| **[MLKEM-TLS]** | [`tlswg/draft-ietf-tls-mlkem`](https://github.com/tlswg/draft-ietf-tls-mlkem) `e652f3d` (2026-09-17) | Read. Primary for what the draft says. Its commit `42544d1` (2026-09-02) changes the references to "HYBRID and ECDHE-MLKEM to their RFC numbers", RFC 9954 and RFC 10024, and records IESG review feedback. |
| **[HYBRID]** | [`dstebila/draft-ietf-tls-hybrid-design`](https://github.com/dstebila/draft-ietf-tls-hybrid-design) `f31e8a3` (2025-09-29) | Read. Its RFC number (9954) comes from [MLKEM-TLS] and [S-IETF]. |
| **[TLS-MLDSA]** | [`tlswg/tls-mldsa`](https://github.com/tlswg/tls-mldsa) `058c2c2` (2026-07-12), `draft-ietf-tls-mldsa.md` | Read. Primary for content. Its IESG state comes from [S-IETF]. |
| **[X509-MLDSA]** | [`lamps-wg/dilithium-certificates`](https://github.com/lamps-wg/dilithium-certificates) `1fcc048` (2025-10-09), published as RFC 9881 | Read. RFC number from [CQRP], [LE] and [S-IETF]. |
| **[X509-SLHDSA]** | [`lamps-wg/x509-slhdsa`](https://github.com/lamps-wg/x509-slhdsa) `b3b216f` (2026-02-23; its last commit: "Update text to match RFC9909") | Read. |
| **[X509-MLKEM]** | [`lamps-wg/kyber-certificates`](https://github.com/lamps-wg/kyber-certificates) `624bcaa` (2025-07-22), published as RFC 9935 | Read. RFC number from [CQRP], which links `datatracker.ietf.org/doc/rfc9935`, and [S-IETF]. |
| **[COMPOSITE]** | [`lamps-wg/draft-composite-sigs`](https://github.com/lamps-wg/draft-composite-sigs) `1bb9f5c` (2026-06-15), `draft-ietf-lamps-pq-composite-sigs.md`, `src/sizeTable.md` | Read. Its status comes from [S-IETF]. |
| **[MTC]** | [`davidben/merkle-tree-certs`](https://github.com/davidben/merkle-tree-certs), now `draft-ietf-plants-merkle-tree-certs`, at `7f5561c` (2026-10-13) | Read: the abstract, the PLANTS charter copy and §"ACME Extensions". |
| **[TAI]** | [`tlswg/tls-trust-anchor-ids`](https://github.com/tlswg/tls-trust-anchor-ids) `a9e8a9d` (2026-10-17) | Read: the abstract and the ACME section. |
| **[S-IETF]** | Search excerpts of rfc-editor.org and datatracker pages for RFCs 9881, 9909, 9935, 9954 and 10024, draft-ietf-tls-mldsa and draft-ietf-lamps-pq-composite-sigs | **Excerpts only.** RFC numbers agree with the primary sources above. Dates and IESG states are not verified. |
| **[BR]** | [`cabforum/servercert`](https://github.com/cabforum/servercert) `3574ae8`, `docs/BR.md`, **Baseline Requirements v2.3.1, 4-Oct-2026** | Read §6.1.5 and §7.1.3. **Primary.** I also searched every branch and commit message for PQ terms and found none. |
| **[CQRP]** | [`GoogleChrome/chromerootprogram`](https://github.com/GoogleChrome/chromerootprogram) `862791c` (2026-10-16): `content/cqrp/{faq,testing,draft-policy}.md`, `content/crp/moving-forward-together.md` | Read. **Primary**: it is the source of googlechrome.github.io/chromerootprogram. The CQRP policy is draft v0.3.0 (2026-08-14). |
| **[LE]** | [`letsencrypt/website`](https://github.com/letsencrypt/website) `f036591`, `content/en/post/2026-06-03-PQ-Certs.md` ("A Post-Quantum Future for Let's Encrypt") | Read in full. **Primary.** |
| **[OSSL]** | [`openssl/openssl`](https://github.com/openssl/openssl) `6d76833` (2026-10-15): `NEWS.md`, `CHANGES.md`, `include/internal/tlsgroups.h`, `include/internal/tlssigalgs.h`, `ssl/t1_lib.c`, `crypto/objects/objects.txt` | Read. **Primary.** |
| **[GO]** | Go toolchain source from `proxy.golang.org`: `go1.27.2` (built 2026-10-02) and `go1.26.0` (`src/crypto/{tls,x509,mldsa}`) | Read. **Primary.** |
| **[NODE]** | `https://nodejs.org/api/crypto.md` and `webcrypto.md` (fetched 2026-10-18; the dist index lists v26.12.0 of 2026-10-14) | Read. Primary. |
| **[PROBE]** | My own tests here: Bun 1.4.2 (the repo's runtime), Node 22.22.0 (OpenSSL 3.5.4), and a Go 1.27.2 TLS server and client that log the offered and negotiated groups | **Observed.** Scripts are in the scratchpad, not the repo. |
| **[PECULIAR]** | npm tarballs of `@peculiar/x509` 1.14.3 (the repo's pin), 2.0.0, 2.1.0 (2026-09-04) and 2.2.0 (2026-10-15) | Read `build/index.d.ts` and the classes. Primary. |
| **[AWS-SDK]** | npm `@aws-sdk/client-kms` and `@aws-sdk/client-acm-pca` 3.1152.0 (2026-10-14): the generated API models (`dist-types/models/{enums,models_0}.d.ts`) | Read. **Primary for the API surface.** It does not say which regions or HSM validation status. |
| **[AZ-SDK]** | npm `@azure/keyvault-keys` 4.10.2 (2026-06-09) and 4.11.0-beta.1 (2026-07-08, API `2026-01-01-preview`) | Read. Primary for the API surface. A missing enum value is strong evidence but not proof that the service lacks it. |
| **[WICG]** | [`WICG/webcrypto-modern-algos`](https://github.com/WICG/webcrypto-modern-algos) `fb7c34b` (2026-09-14) | Read. A Community Group draft (`specStatus: CG-DRAFT`). |
| **[APPLE]** | [WWDC25 session 314, "Get ahead with quantum-secure cryptography"](https://developer.apple.com/videos/play/wwdc2025/314/), transcript | Read. Primary (Apple). |
| **[CF]** | [`cloudflare/cloudflare-docs`](https://github.com/cloudflare/cloudflare-docs) `887ef7a` (2026-10-18): `src/content/docs/ssl/post-quantum-cryptography/*.mdx` | Read. **Primary for Cloudflare's own products.** Its third-party support list is Cloudflare's summary, so treat it as secondary for other vendors. |
| **[S-APPLE]**, **[S-FF]**, **[S-MS]**, **[S-AZ]**, **[S-INTUNE]**, **[S-WEBCRYPTO]** | Search excerpts: the Apple Platform Security guide (support.apple.com), Firefox release notes and enterprise policy docs, third-party write-ups of Windows/AD CS PQ updates, Azure, Intune, and a blink-dev "Intent to Experiment" with an Edge origin trial | **Excerpts only. Mostly secondary.** Microsoft facts in particular have no first-party source here. |
| **[S-NIST]**, **[S-CNSA]**, **[S-NCSC]**, **[S-EU]**, **[S-FIPS206]** | Search excerpts about NIST IR 8547, the Federal Register FIPS 203/204/205 notice, NSA CNSA 2.0, the NCSC PQC migration timelines and the EU coordinated roadmap | **Excerpts only.** [LE] also cites IR 8547, CNSA 2.0 and the EU roadmap, which corroborates them. |
| **[CODE]** | This repository at the working tree of 2026-10-18 | Read. |

## 1. Key exchange in TLS 1.3

### 1.1 Standards status

- **Hybrid groups: RFC 10024** ("Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3"), Standards Track, published around August 2026 [ECDHE-MLKEM; S-IETF]. IANA registered three TLS Supported Groups, which the text says "are to be used with the final version of ML-KEM … {{NIST-FIPS-203}}" [ECDHE-MLKEM §IANA]:

  | Value | Name | DTLS-OK | Recommended |
  |---|---|---|---|
  | 4588 (0x11EC) | `X25519MLKEM768` | Y | **Y** |
  | 4587 (0x11EB) | `SecP256r1MLKEM768` | Y | N |
  | 4589 (0x11ED) | `SecP384r1MLKEM1024` | Y | N |

  The RFC also marks the pre-standard `X25519Kyber768Draft00` (25497) and `SecP256r1Kyber768Draft00` (25498) as `D`, deprecated [ECDHE-MLKEM §"Obsoleted Supported Groups"]. I did not read the IANA registry itself. The codepoints agree with the constants in OpenSSL [OSSL `include/internal/tlsgroups.h`] and Go [GO `crypto/tls/common.go`: `X25519MLKEM768 CurveID = 4588`, `SecP256r1MLKEM768 = 4587`, `SecP384r1MLKEM1024 = 4589`].
- **The hybrid construction itself: RFC 9954** ("Hybrid Key Exchange in TLS 1.3"), Informational, dated July 2026 by rfc-editor.org [HYBRID; MLKEM-TLS commit `42544d1`; S-IETF].
- **Pure ML-KEM: draft-ietf-tls-mlkem**, intended Informational. It has been through IESG review (2026-09) but is not yet an RFC as far as I can tell [MLKEM-TLS]. It registers `MLKEM512` 512 (0x0200), `MLKEM768` 513 (0x0201) and `MLKEM1024` 514 (0x0202), **all Recommended = N**, which RFC 9847 defines as "not been evaluated by the IETF … no statement about the suitability" [MLKEM-TLS §IANA].
- **ML-KEM itself is FIPS 203**, effective 2024-08-14 [S-NIST, Federal Register notice].
- **Newer groups.** OpenSSL master also carries `MLKEM512X25519` (0x11EA) and `SecP256r1MLKEM512` (0x11E9) "for the newly assigned IANA codepoints per draft-rosomakho-tls-ecdhe-mlkem512-00" [OSSL `CHANGES.md` 4.1→4.2, `tlsgroups.h`]. These are early-stage, so we only watch them.

### 1.2 Key exchange is not a certificate property

The group is negotiated between the TLS client and the TLS server, in the `supported_groups` and `key_share` extensions [MLKEM-TLS §"Construction", citing RFC 9846 §4.3.7–4.3.8]. Nothing in the certificate selects or constrains it: a classical ECDSA or RSA certificate works with `X25519MLKEM768`. So the platform has nothing to issue for PQ key exchange. Its options are:

1. **The platform's own TLS.** I tested Bun 1.4.2 against a Go 1.27.2 peer that logs the handshake [PROBE]:
   - `fetch` and `node:tls` `connect` (used by `server/src/audit/audit-transport.ts`) offer `[X25519MLKEM768 X25519 P-256 P-384]` and negotiate `X25519MLKEM768`.
   - `Bun.serve` with TLS negotiates `X25519MLKEM768` with a Go client.
   - So the platform's outbound calls (ACME, DNS Providers, audit) and any TLS that Bun terminates are already hybrid PQ, with no code. Whatever terminates TLS in production is not in this repo (`docker-compose.yml` runs only test services), and **is unknown**.
2. **The Agent.** The Agent's module says `go 1.25` [CODE `agent/go.mod`], and its client sets only `MinVersion` [CODE `agent/internal/platform/client.go`]. From Go 1.24 the default `CurvePreferences` includes `X25519MLKEM768`, and from Go 1.26 also `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` [GO `crypto/tls/common.go` comment on `CurvePreferences`; `defaults.go`]. So the Agent-to-platform channel is hybrid PQ already, unless someone sets `GODEBUG=tlsmlkem=0`.
3. **The Endpoints, where the value lies.** Deployment Scripts, written by Organization Administrators, configure the servers the certificates land on [CODE `CONTEXT.md` "Deployment Script"]. The platform does not configure TLS servers, so it cannot turn PQ key exchange on. Where these servers stand:
   - OpenSSL 3.5.0 (2025-04-08) "changed [the default groups] to include and prefer hybrid PQC KEM groups" and sends `X25519MLKEM768` and `X25519` key shares [OSSL `NEWS.md`].
   - The current default list starts `?*X25519MLKEM768:?SecP256r1MLKEM768:?curveSM2MLKEM768 / ?*X25519:?secp256r1 / …` [OSSL `ssl/t1_lib.c` `TLS_DEFAULT_GROUP_LIST`].
   - So nginx, Apache or HAProxy linked against OpenSSL 3.5+ gets it by default, and an older OpenSSL does not. Cloudflare's list reaches the same conclusion for NGINX, Caddy 2.10+ and Traefik 3.4.2+ [CF `pqc-support.mdx`, secondary for those products].
   - Windows Schannel: hybrid key exchange reportedly arrived with the July 2026 updates, **disabled by default** [S-MS, secondary, unverified].
4. **Inventory: the useful platform feature.** Endpoints, Sightings and Discovered Certificates are a planned bounded context ("Discovery (future)") [CODE `CONTEXT.md`]. When Discovery is built, record per Sighting the TLS version and **the negotiated group**, and offer a filter such as "Endpoints without PQ key exchange". This is the "discovery exercise" that the NCSC's 2028 milestone asks for [S-NCSC]. Two requirements:
   - A scanner must offer the PQ groups and report the one chosen. Go's `tls.ConnectionState.CurveID` does this and names `X25519MLKEM768` [PROBE].
   - I found no Bun API that exposes the negotiated group. That is **unverified**, so a scanner may belong in the Agent (Go) rather than the server.

### 1.3 Clients

- **Chrome/Edge**: `X25519MLKEM768` is the default from 131 [CF, secondary]. Chrome's own root-program pages say Chrome "has mitigated this risk through the deployment of post-quantum key exchange" [CQRP `moving-forward-together.md`].
- **Firefox**: hybrid X25519+ML-KEM-768 is on by default, per Mozilla's enterprise policy docs [S-FF]. Cloudflare's list says desktop 132+ and Android 145+ [CF, secondary].
- **Apple**: "Starting in iOS 26, quantum-secure encryption in TLS is enabled by default on Apple operating systems, for … URLSession, and Network.framework". Secure Transport "will not support quantum-secure TLS" [APPLE]. The Apple Platform Security guide names the group as `X25519MLKEM768` [S-APPLE].
- **Libraries**:
  - OpenSSL 3.5+ (default, as above) [OSSL].
  - Go 1.24+ (default) [GO].
  - Node ≥ 24.5 / 22.20 (default via bundled OpenSSL 3.5) [CF]. My Node 22.22.0, which reports OpenSSL 3.5.4, offered `X25519MLKEM768` first [PROBE].
  - Bun 1.4.2 (default) [PROBE].

## 2. Signatures and certificate keys

### 2.1 Algorithms and their X.509 specifications

| Algorithm | Standard | X.509 spec | TLS 1.3 spec | Sizes (bytes) |
|---|---|---|---|---|
| **ML-DSA-44 / -65 / -87** | FIPS 204 (effective 2024-08-14) [S-NIST] | **RFC 9881** (Proposed Standard, Oct 2025) [X509-MLDSA; S-IETF]. OIDs `2.16.840.1.101.3.4.3.17/18/19`, parameters absent. **Pure ML-DSA only: HashML-DSA "MUST NOT" be used.** Pre-hashing is done with "External μ" [X509-MLDSA §externalmu, §sec-disallow-hash]. | **draft-ietf-tls-mldsa**, intended Informational. SignatureSchemes `mldsa44` 0x0904, `mldsa65` 0x0905, `mldsa87` 0x0906, all Recommended = N [TLS-MLDSA §IANA]. A July 2026 datatracker snapshot shows "Approved-announcement to be sent", with IANA "On Hold" [S-IETF]. **Not yet an RFC.** | pk 1312 / 1952 / 2592; sig 2420 / 3309 / 4627 [COMPOSITE `sizeTable.md`; GO `crypto/mldsa`] |
| **SLH-DSA** (12 parameter sets) | FIPS 205 [S-NIST] | **RFC 9909** (Proposed Standard, Dec 2025) [X509-SLHDSA; S-IETF] | OpenSSL assigns `slhdsa_*` sigalgs 0x0911… [OSSL `tlssigalgs.h`]. I found no IETF TLS draft. | sig **7,856** (128s) to **49,856** (256f) [X509-SLHDSA tab-strengths] |
| **FN-DSA** (Falcon) | **FIPS 206 not final.** A May 2026 IETF draft still calls it "forthcoming" [S-FIPS206] | draft-ietf-lamps-fn-dsa-certificates-00 [S-FIPS206] | none found | not checked |
| **Composite ML-DSA** (ML-DSA + RSA/ECDSA/EdDSA in one key) | none | **draft-ietf-lamps-pq-composite-sigs-19**, in the RFC Editor queue [S-IETF]. The history may show it was pulled from the queue once (unverified). It recommends `id-MLDSA65-ECDSA-P256-SHA512` by default, `id-MLDSA87-ECDSA-P384-SHA512` for Level 5 only [COMPOSITE §sec-impl-profile] | none found | e.g. MLDSA65-ECDSA-P256: pk 2017, sig ≤ 3381 [COMPOSITE] |
| **ML-KEM in certificates** | FIPS 203 | **RFC 9935** [X509-MLKEM; CQRP; S-IETF] | **Not usable for TLS server authentication.** "To be used in TLS, ML-KEM certificates could only be used as end-entity identity certificates and would require significant updates to the protocol" (AuthKEM) [X509-MLKEM §Applicability]. Its intended use is CMS. | — |

For comparison: ECDSA P-256 has a 64-byte signature and RSA-2048 a 256-byte one. "A typical Web PKI handshake today carries five signatures and two public keys", so with ML-DSA "a single TLS handshake [goes] well past 10 kilobytes" [LE].

### 2.2 Public (ACME) certificates: none, and none coming in X.509 form

- **The Baseline Requirements allow only RSA (≥ 2048, a multiple of 8) and ECDSA on P-256/P-384/P-521:** "No other algorithms or key sizes are permitted" [BR §6.1.5, v2.3.1]. I found no ballot, branch or commit that permits PQ keys [BR].
- **Chrome:** "Chrome has no immediate plan to add traditional X.509 certificates containing post-quantum cryptography to the Chrome Root Store and will only do so as a last resort" [CQRP `moving-forward-together.md`]. Its draft CQRP policy restates this [CQRP `draft-policy.md` §1].
- **Chrome's PQ path for the public web is Merkle Tree Certificates (MTCs)**, in a separate Chrome Quantum-resistant Root Store (CQRS). Phases from [CQRP `faq.md`]:
  - Phase 1, a feasibility study with Cloudflare, is underway.
  - Phase 2, Q1 2027: public MTC bootstrapping.
  - Phase 3, Q3 2027: the CQRS launches, with optional downgrade protection.
  - A test root store needs Chrome 152 (Canary) [CQRP `testing.md`].
- **Under the CQRS draft policy, subscriber certificates keep BR algorithms or may use pure ML-DSA-44/65/87.** HashML-DSA is forbidden. CA cosigner keys are ML-DSA-44 only [CQRP `draft-policy.md` §2.4.3].
- **Let's Encrypt** "is planning to support Merkle Tree Certificates as the path forward". It targets "late 2026 for a staging environment that issues MTCs, and 2027 for a production-ready environment", and is "tracking" RFC 9881 and draft-ietf-tls-mldsa. "Nothing changes today." It also says "Some of the changes coming will require client-side support" in ACME clients [LE].
- **What MTCs ask of an ACME client** [MTC §"ACME Extensions"; TAI §"ACME Extension"]:
  - Send `Accept: application/pem-certificate-chain-with-properties`, and parse the `CertificatePropertyList` (trust anchor IDs).
  - Fetch the new `acme-optional-alternate` link. It may answer `202` with `Retry-After` until the next landmark, and the client "SHOULD NOT block deployment" on it.
  - Keep and deploy **more than one chain per issuance**: the standalone one, and the landmark-relative one when it arrives.
  - The MTC spec is a WG draft that still changes weekly (last commit 2026-10-13) [MTC].

### 2.3 Private PKI: ML-DSA is usable now

- **Chrome**: "Beginning in Chrome 150, Chrome supports ML-DSA in private PKI hierarchies, making it possible to test non-MTC post-quantum X.509 certificates locally or within enterprise environments" [CQRP `faq.md`]. The test page calls Chrome 152 "currently Chrome Canary", so 150 should be Stable by now; that is my inference.
- **Servers**:
  - OpenSSL 3.5+ has ML-DSA and SLH-DSA, and puts all three ML-DSA sigalgs first in its default TLS signature algorithms [OSSL `CHANGES.md` 3.5.0; `ssl/t1_lib.c` `tls12_sigalgs`].
  - So nginx with OpenSSL 3.5 can serve an ML-DSA certificate [CF, secondary].
  - Go 1.27 adds public `crypto/mldsa`, ML-DSA in `crypto/x509` (parse, PKCS #8, and as a signer for certificates and CSRs) and TLS SignatureSchemes 0x0904–0x0906 [GO 1.27.2]. Go 1.26.0 has none of these [GO 1.26.0].
- **Cloudflare**: "Since mid-2026", its Custom Origin Trust Store "trusts an ML-DSA certificate authority when validating the origin server certificate", and Authenticated Origin Pulls presents an ML-DSA client certificate [CF `pqc-to-origin.mdx`]. This is a concrete use today for **Private CA** ML-DSA server certificates on origins behind Cloudflare.
- **Windows**: AD CS on Windows Server 2025 reportedly gained ML-DSA-44/65/87 in a May 2026 update. CNG ML-KEM/ML-DSA went GA in Nov 2025, and TLS use is called "limited" [S-MS, secondary]. **Whether Schannel accepts ML-DSA server certificates is unknown.**
- **Apple**: CryptoKit has ML-DSA as a signature API, with Secure Enclave support [APPLE]. **Whether Apple's TLS validates ML-DSA certificate chains is unknown.** I found no statement either way, and Cloudflare marks Safari signatures "Not yet" [CF].

## 3. What our stack can do today

| Component | Classical today | PQ support found | Source |
|---|---|---|---|
| Server runtime, Bun 1.4.2 (`node:crypto`, `crypto.subtle`) | — | `generateKeyPairSync('ml-dsa-44/65/87')` and `'ml-kem-768'` work. ML-DSA-65 SPKI (1974 bytes) re-parses as `asymmetricKeyType: 'ml-dsa-65'`, and sign/verify works (3309-byte signature). `subtle.generateKey` works for `ML-DSA-65` and `ML-KEM-768`. **`slh-dsa-*` is refused.** | [PROBE] |
| Node 22.22.0 (for comparison) | — | No ML-DSA or ML-KEM. Node's docs add WebCrypto ML-DSA/ML-KEM in v24.7.0 and `node:crypto` ML-DSA/SLH-DSA with "OpenSSL >= 3.5". **I found no "External μ" signing option in Node's API**, only a `context` parameter. | [PROBE; NODE] |
| X.509 library, `@peculiar/x509` (pinned **1.14.3**) | RSA, EC, Ed | 1.14.3 and 2.0.0 have none. **2.1.0 (2026-09-04) adds `MlDsaAlgorithm` and `SlhDsaAlgorithm`** (parameters absent), via `@peculiar/asn1-x509-post-quantum`. The repo would need a **major-version upgrade** (1 → 2), whose breaking changes I have not reviewed. | [PECULIAR; CODE `package.json`] |
| Agent (Go, `go 1.25`; local toolchain 1.24.7) | `ecdsa-p256/p384`, `rsa-2048/3072/4096` | Needs **Go 1.27** for `crypto/mldsa` and ML-DSA CSRs | [GO; CODE `agent/internal/keystore/keystore.go`] |
| AWS KMS | — | `KeySpec` has `ML_DSA_44/65/87` and `SigningAlgorithm` `ML_DSA_SHAKE_256`. `MessageType` `EXTERNAL_MU` takes "64-byte representative μ used in ML-DSA signing as defined in NIST FIPS 204 Section 6.2", so digest-style signing, as ADR 0007 needs, is possible | [AWS-SDK] |
| AWS Private CA | — | `KeyAlgorithm` and `SigningAlgorithm` have `ML_DSA_44/65/87` | [AWS-SDK] |
| Azure Key Vault | — | **No ML-DSA in `KnownJsonWebKeyType`** (`EC`, `EC-HSM`, `RSA`, `RSA-HSM`, `oct`, `oct-HSM`), even in the `2026-01-01-preview` API. An August 2026 review also says Managed HSM lists no ML-DSA | [AZ-SDK; S-AZ] |
| Browser WebCrypto (CSR Generator) | ECDSA, RSA | The spec is a Community Group draft covering ML-KEM, ML-DSA, SLH-DSA and more [WICG]. Chrome is at "Intent to Experiment" (June 2026, Android 150 DevTrial), and an Edge origin trial ends 2026-10-20. I found nothing for Safari or Firefox [S-WEBCRYPTO] | [WICG; S-WEBCRYPTO] |
| Intune / SCEP | RSA device keys | No evidence Intune SCEP/PKCS profiles or Cloud PKI support PQ keys [S-INTUNE]. **The platform's SCEP is RSA-only by design**: "SCEP encrypts its response to the device's key, which only RSA can do" [CODE `server/src/enrollment/enrollment-profile-kinds.ts`]. An ML-DSA device key cannot receive a SCEP response at all | [S-INTUNE; CODE] |

## 4. Government guidance and timelines

- **NIST IR 8547** proposes deprecating RSA, ECDSA, ECDH and finite-field DH after 2030 and disallowing them after 2035, in favour of FIPS 203/204/205. It was still an **initial public draft** (Nov 2024) in every source I found, as of mid-2026 [S-NIST]. [LE] describes it the same way ("NIST's draft transition guidance would deprecate RSA-2048 and P-256 after 2030 and disallow them after 2035"). Excerpts disagree on whether the 2030 date covers only 112-bit strength, so check the primary text before quoting it.
- **NSA CNSA 2.0** applies to National Security Systems. It names ML-KEM-1024, ML-DSA-87, AES-256 and SHA-384/512. For "web browsers/servers and cloud services" it says to support and prefer CNSA 2.0 by 2025 and use it exclusively by 2033 [S-CNSA]. [LE] confirms the 2030–2035 schedule. In TLS terms this means `SecP384r1MLKEM1024` or `MLKEM1024`, and ML-DSA-87 certificates, but those certificates are not obtainable publicly (§2.2).
- **UK NCSC**:
  - by 2028, define goals, carry out "a full discovery exercise" and build a plan;
  - by 2031, finish the highest-priority migrations;
  - by 2035, finish all migrations [S-NCSC].
- **EU coordinated roadmap** (NIS Cooperation Group, June 2025): start by end of 2026, high-risk use cases by end of 2030, everything by 2035. It favours hybrids [S-EU; LE].
- **Industry**: Google has said it will migrate its services by 2029, and Cloudflare "is targeting 2029 to be fully post-quantum secure" [LE; CF `index.mdx`].

Every timeline is about migrating **by 2030–2035**, and authentication is the harder half. The certificate the platform can obtain publicly stays classical until MTCs arrive (2027 at the earliest).

## 5. Where key types live in the code

Every place that names or checks a key type, for a change that adds one:

- **The platform's key algorithm vocabulary**: `server/src/pki/csr.ts`:
  - `KEY_ALGORITHMS = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"]`;
  - `keyAlgorithmOf()` maps `createPublicKey(spki).asymmetricKeyType` to a name. Under Bun this already returns `'ml-dsa-65'` for an ML-DSA key [PROBE], so the change is one branch;
  - `parseCsr()` calls `Pkcs10CertificateRequest.verify()` from `@peculiar/x509`, which needs ≥ 2.1 to verify an ML-DSA CSR.
  
  Consumers of `KEY_ALGORITHMS` / `KeyAlgorithm`:
  - `server/src/certificates/managed-certificates.ts` (create) and `managed-certificate-reader.ts`;
  - `server/src/certificates/inventory-filters.ts` (the `keyAlgorithm` filter);
  - `server/src/certificates/names-and-csr.ts` (CSR key must match);
  - `server/src/issuance/renewal-routes.ts`, `server/src/certificates/name-change-routes.ts`;
  - `server/src/deployment/deployments.ts` and the `deployment.generate_key` payload (`agent/contract/openapi.json`);
  - `server/src/private-ca/private-ca.ts` (`keyAlgorithm` of a Private CA, default `ecdsa-p256`).
  
  The DB columns are free `text` typed as `KeyAlgorithm` [CODE `server/src/platform/db/schema.ts` lines 45, 139], so **no migration is needed** to add a value.
- **The issuer must gate the key type.** A Managed Certificate's issuer is an ACME CA or a Private CA's Issuing CA [CODE `managed-certificates.ts`; `CONTEXT.md` "Certificate Authority"]. An ML-DSA key must be refused for an ACME issuer, which the BRs forbid, at create time (`issuerAsked`) and wherever the issuer can change.
- **KMS seam**: `server/src/platform/crypto/kms.ts` and ADR 0007:
  - `SIGNATURE_HASH: Record<KeyAlgorithm, "SHA-256" | "SHA-384">` and "signs a digest" assume a hash-then-sign scheme;
  - for ML-DSA the "digest" is **μ** (64 bytes, computed from the public key and the message), which AWS KMS accepts as `EXTERNAL_MU` [AWS-SDK; X509-MLDSA §externalmu];
  - the local implementation (`generateKeyPair`, `signDigest`) would need an ML-DSA path that signs from μ. Bun/Node expose no such option [NODE], so it would need a library or to sign the whole message: **unknown, needs a spike**;
  - the contract test `server/test/support/kms-signing-contract.ts` would gain ML-DSA cases.
- **X.509 assembly and display**:
  - `server/src/private-ca/private-ca.ts` and `server/src/private-ca/crl.ts` (CA certificates, CSRs, CRLs through the `Signer`);
  - `server/src/pki/ca-certificates.ts`;
  - `server/src/pki/certificate-facts.ts` (`SIGNATURE_SCHEMES` has no ML-DSA label; it falls back to the algorithm name).
- **Agent key generation**: `agent/internal/keystore/keystore.go` `generate()` (and `x509.CreateCertificateRequest`), plus `agent/go.mod` raised to Go 1.27.
- **Web**:
  - `web/src/lib/csr-generator.ts` `KEY_ALGORITHMS`, `keyParams()` and `defaultHash()`. Browsers ship no ML-DSA WebCrypto, so PQ stays out of the generator;
  - the pickers in `web/src/pages/new-managed-certificate-dialog.tsx`, `new-deployment-dialog.tsx`, `private-cas.tsx`, `managed-certificates.tsx`, `managed-certificate-overview.tsx`, `managed-certificate-details.tsx`, `web/src/components/csr-generator.tsx`;
  - `web/package.json` also pins `@peculiar/x509` 1.14.3 (with `web/src/lib/csr-signature.ts`).
- **SCEP / Enrollment Profiles**: `DEVICE_KEY_TYPES` in `server/src/enrollment/enrollment-profile-kinds.ts`, `allowedKeyTypes` in `enrollment-profiles.ts`, `keyType` in `device-certificates.ts`, and `server/drizzle/0043_device_certificate_key_type.sql`. These stay RSA (§3).
- **ACME client, for MTCs later**: `server/src/issuance/acme/` (the certificate download, the `Accept` header and alternates). The single `chainPem` per Certificate [CODE `deployment.run` payload in `agent/contract/openapi.json`] would need to become several chains.

## 6. Recommendation

### Support now

1. **PQ key exchange: confirm, do not build.**
   - The platform's Bun TLS and the Go Agent already negotiate `X25519MLKEM768` by default [PROBE; GO]. Add a test that pins this, for example by asserting the group a Go peer sees, so a runtime upgrade cannot silently drop it.
   - Find out what terminates TLS in production (unknown).
   - In the docs and example Deployment Scripts, tell Organization Administrators that PQ key exchange is a server setting: OpenSSL ≥ 3.5 (default), or an explicit group list such as `X25519MLKEM768:X25519:…` for nginx/Apache; Windows needs opt-in [OSSL; S-MS]. Let's Encrypt calls turning it on "one of the highest-leverage things you can do this year" [LE].
2. **Classical key types stay as they are for ACME** (ECDSA P-256/P-384, RSA 2048–4096). The BRs allow nothing else [BR].
3. **When Discovery is built, record the negotiated group per Sighting** and show "no PQ key exchange" in the inventory (§1.2 item 4). That is the platform's real contribution to the key-exchange migration, and the discovery step the NCSC and EU ask for first [S-NCSC; S-EU]. **Trigger**: the Discovery feature starting. Put the scanner where the negotiated group is observable (the Go Agent).

### Behind a flag, Private CA only

4. **ML-DSA (44/65/87, default 65; 87 for CNSA 2.0 customers) as a Private CA key algorithm and as a leaf key algorithm for Managed Certificates issued by a Private CA.** Pure ML-DSA only; never HashML-DSA [X509-MLDSA; CQRP].
   - **Why now-ish**: RFC 9881 is final. Chrome 150 validates ML-DSA in private hierarchies, OpenSSL 3.5 serves it, Cloudflare's origin trust store accepts ML-DSA CAs, AWS KMS and AWS Private CA have ML-DSA keys, and Bun 1.4.2 can generate, parse and verify them [X509-MLDSA; CQRP; OSSL; CF; AWS-SDK; PROBE].
   - **Why a flag**:
     - draft-ietf-tls-mldsa is not yet an RFC;
     - Windows Schannel and Apple's acceptance of ML-DSA chains is unknown;
     - Azure Key Vault has no ML-DSA, so an Organization whose CA keys must be in Azure cannot use it [AZ-SDK].
   - **Constraints to build in**:
     - the whole hierarchy (root, Issuing CA, leaf) uses ML-DSA, since an ML-DSA leaf under an ECDSA CA gives no PQ authentication. `private-ca.ts` already uses one `keyAlgorithm` for root and Issuing CAs;
     - refuse ML-DSA leaf keys for ACME issuers;
     - keep it out of the browser CSR Generator, since no browser ships ML-DSA WebCrypto [S-WEBCRYPTO];
     - Agent key custody only once the Agent is on Go 1.27.
   - **Work**:
     - `@peculiar/x509` 1.14.3 → ≥ 2.1 (server and web);
     - ML-DSA in `csr.ts`;
     - a μ-based path in the `Kms` seam (AWS `EXTERNAL_MU`; local implementation to spike) and an ADR 0007 amendment for the "one hash per algorithm" rule;
     - Go 1.27 in `agent/`;
     - a Private-CA-only option in the web pickers.
   - **Trigger to make it generally available (unflagged)**:
     - draft-ietf-tls-mldsa published as an RFC;
     - **and** confirmed ML-DSA chain validation in at least Windows (Schannel) or Apple platforms, as well as Chrome;
     - **and** either Azure Key Vault ML-DSA or an explicit decision that ML-DSA CAs are AWS-only.

### Watch, do not build yet

5. **Merkle Tree Certificates through ACME.** The changes would be: the ACME client's `Accept` header, `acme-optional-alternate` with `202`/`Retry-After`, trust anchor IDs, several chains per Certificate, and Deployment Scripts that install more than one chain [MTC; TAI]. **Trigger**: Let's Encrypt staging issuing MTCs (targeted "late 2026") and the PLANTS draft stabilising. Start the client work then, since Let's Encrypt asks ACME clients to be "ready when the issuance side is" [LE]. Production follows Chrome's Q3 2027 CQRS [CQRP].
6. **ML-DSA in public X.509 certificates.** The BRs forbid it, Chrome calls it a "last resort", and Let's Encrypt only tracks it [BR; CQRP; LE]. **Trigger**: a CA/B Forum ballot amending BR §6.1.5/§7.1.3, or Let's Encrypt announcing ML-DSA X.509 issuance.
7. **Composite ML-DSA.** It is still in the RFC Editor queue, possibly after a pull from it [S-IETF], and OpenSSL, Go and Bun have no implementation [OSSL; GO; PROBE]. **Trigger**: an RFC, support in a mainstream TLS library, and a customer under a hybrid-signature mandate.
8. **SLH-DSA.** RFC 9909 is final, but signatures run from 7.8 to 49.9 KB [X509-SLHDSA]. AWS KMS has no SLH-DSA key spec [AWS-SDK], and Bun refuses `slh-dsa-*` [PROBE]. At most, a long-lived Private CA *root* could use it someday. **Trigger**: SLH-DSA in AWS KMS (or Azure) and a customer asking for a hash-based root.
9. **FN-DSA.** FIPS 206 is not final [S-FIPS206]. **Trigger**: FIPS 206 published, plus an X.509 RFC.
10. **ML-KEM certificates (RFC 9935).** They cannot authenticate a TLS 1.3 server [X509-MLKEM]. **Trigger**: none foreseeable for TLS; revisit only for CMS or S/MIME scope.
11. **PQ device keys over SCEP / Intune.** These are structurally blocked: SCEP needs an encryption-capable device key [CODE], and I found no Intune PQ support [S-INTUNE]. **Trigger**: Intune announcing PQ key types in SCEP/PKCS profiles, together with a defined SCEP (or successor) flow for them.
12. **Pure ML-KEM groups and `SecP384r1MLKEM1024`.** These are server configuration only. The platform needs nothing beyond a Discovery Sighting showing which group was used (item 3).

### Genuinely unknown or unverified

- The IANA registry contents, the RFC publication dates, and the IESG state of draft-ietf-tls-mldsa and the composite draft (no access to IANA, datatracker or rfc-editor; excerpts only).
- Every Microsoft fact (Schannel PQ key exchange, ML-DSA in AD CS, Intune), Azure Managed HSM PQ plans, and Apple's validation of ML-DSA certificate chains.
- NIST IR 8547's final status and exact wording, and the primary text of CNSA 2.0, the NCSC timelines and the EU roadmap.
- What terminates TLS in production.
- Whether Bun exposes the negotiated TLS group.
- How the local `Kms` would sign ML-DSA from μ.
- The breaking changes in `@peculiar/x509` 2.x.
