# Spec: CSR Generator

Status: ready-for-agent

## Problem Statement

An Owner who keeps their own private key (Key Custody: Owner) must hand the platform a CSR. Today the web app only offers a textarea to paste one into, in three places: creating a Managed Certificate, proposing a Name Change, and uploading a new CSR for Renewal. Producing that CSR means leaving the portal to run `openssl` or a vendor tool, getting the key algorithm and the names exactly right (the server refuses a CSR whose key algorithm or names differ from the Managed Certificate's), and keeping the key safe. People who are not PKI specialists get this wrong, and they get it wrong after they have already filled in a form.

## Solution

A **CSR Generator** in the web app that makes a key pair and a CSR entirely in the user's browser, so the platform never sees the private key (ADR 0002). It stands on its own under a new **Tools** item in the Organization sidebar, and the same component is embedded in the three forms that take a CSR, with the names and key algorithm filled in and locked by the form. The user downloads or copies the key and the CSR; only the CSR is ever submitted.

## User Stories

1. As a Member, I want to generate a key and a CSR in the portal, so that I do not need `openssl` to propose a Managed Certificate.
2. As an Owner, I want the generator to use the names and key algorithm of my Managed Certificate and not let me change them, so that the CSR cannot be refused for not matching.
3. As a user, I want the key generated in my browser and never sent anywhere, so that the platform cannot expose it.
4. As a user, I want to download or copy both the key (PKCS#8 PEM) and the CSR (PEM), so that I can keep the key and submit the CSR.
5. As a user, I want to be stopped from using a CSR until I have saved its key, and warned before I leave the page with an unsaved key, so that I do not lose the only copy.
6. As a user preparing a CSR for another CA, I want to give optional Organization, Organizational Unit, Country, State and Locality, so that the CSR carries them.
7. As a user, I want to choose the key algorithm (ECDSA P-256 or P-384, RSA 2048, 3072 or 4096) and the signature hash, with sane defaults, so that the common case is one click and the uncommon one is possible.
8. As a user, I want to be told when I pick a hash weaker than my key, or paste a CSR signed with SHA-1, MD5 or RSA-PSS, so that I find out before the CA refuses it.
9. As a user, I want to still paste my own CSR everywhere, so that people with their own tooling are not affected.

## Implementation Decisions

**Key generation.** In the browser only, with WebCrypto, building the CSR with `@peculiar/x509` (already a root dependency; the server uses it to parse CSRs). A spike comes first: bundle it with Vite and generate a CSR in the browser pane. If it does not work there, use PKI.js instead. The key is generated extractable, exported once as PKCS#8, and dropped from component state when the user leaves.

**Rules are the platform's, everywhere, including the Tools page.**
- Names: DNS names only, wildcards allowed as a leading `*.`, no IP addresses, no underscores, at most 100. Checked inline with the same rules as `normalizeName` in `server/src/names.ts`. The web package shares no code with the server, so the rules are re-implemented in a small pure module and pinned to the server's by a test.
- CN: one of the entered names, or none; defaults to the first name. Never free text, because the server counts the CN as one of the CSR's names.
- Optional subject fields: Organization, Organizational Unit, Country (exactly two letters), State, Locality; empty ones are left out; in a collapsed "Subject details (optional)" section with a note that Let's Encrypt ignores them. No `emailAddress`, `serialNumber` or free-form OIDs.
- Key algorithm: the server's five, default ECDSA P-256; locked to the Managed Certificate's own where a flow has one (Name Change, Renewal).
- Signature algorithm, under "Advanced": ECDSA with SHA-256, SHA-384 or SHA-512; RSA with RSASSA-PKCS1-v1_5 and SHA-256, SHA-384 or SHA-512. Defaults: SHA-256 for P-256, SHA-384 for P-384, SHA-256 for RSA. Changing the key algorithm resets the hash to its default unless the user's choice is still valid. No SHA-1, MD5 or RSA-PSS.

**Output.** Unencrypted PKCS#8 PEM for the key and PEM for the CSR, each with a download and a copy button; the key is behind a "show" toggle with a plain warning that it is never sent to the platform and cannot be recovered. No passphrase encryption in v1.

**Key safety.** A `beforeunload` warning while a generated key has not been downloaded or copied. In the embedded forms, "Use this CSR" stays disabled until the key has been saved. The key is cleared on unmount.

**Warnings are non-blocking and the server does not change.** `parseCsr` keeps checking only that the signature verifies. The generator shows a soft note when the hash is weaker than the key (SHA-256 with P-384). The three pasted-CSR textareas show a warning when the pasted CSR is signed with SHA-1, MD5 or RSA-PSS, by decoding just the signature algorithm with `@peculiar/x509`; it never blocks the submit and shows nothing else about the CSR.

**Placement.** A "Tools" group in the Organization sidebar (`web/src/lib/navigation.ts`), visible to every Member with no permission check, with the page at `/organizations/:id/tools/csr`. No server route, permission or Audit Event: generation is client-side, and the submission already records the CSR's fingerprint. The component takes its inputs (names, key algorithm, whether they are locked) as props, so the same component serves the Tools page and the three forms. The pasted-CSR path stays everywhere.

**Docs.** An addendum to `docs/adr/0002-platform-never-holds-private-keys.md` (the platform's web code runs in the user's browser and never sends the key anywhere), and a "CSR Generator" entry in `CONTEXT.md`.

## Testing Decisions

- The generator is a pure web module (no DOM beyond WebCrypto) that imports neither `web/src/lib/api.ts` nor `fetch`.
- A server test imports it, generates a CSR for each of the five key algorithms, and checks the real `parseCsr` accepts it with the right algorithm and names. It also pins the web name rules against `normalizeName` on a fixture list, and asserts the module's imports exclude `api.ts` and `fetch`. The server's `tsconfig`, which does not cover `web/`, may need a path or include for this.
- That the browser never sends the key anywhere is a scenario added to the end-to-end smoke tests (`27-e2e-smoke.md`).
- No new test runner for the web package.

## Out of Scope

- A general CSR decoder or checker (the pasted-CSR warning reads the signature algorithm and nothing else).
- Importing an existing key to sign a CSR.
- Certificate chain tools.
- Remembering anything between visits, such as recently used subject fields.
- Passphrase-encrypted keys.
- A hand-off from the Tools page into Managed Certificate creation.
- Any server-side enforcement of the signature algorithm.
