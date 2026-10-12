# 01: CSR Generator and the Tools page

**What to build:** A user opens **Tools** in the Organization sidebar, enters names, optionally changes the key and signature algorithms and fills in subject details, and gets a key and a CSR made in their browser, which they download or copy. This is the whole generator, standing alone; the forms that take a CSR do not use it yet. See `spec.md` for the rules it follows (the platform's name rules, CN from the names, the five key algorithms, signature algorithm choice with defaults, optional subject fields, PKCS#8 and CSR PEM output).

**Blocked by:** none

**Status:** ready-for-agent

- [ ] Spike first: `@peculiar/x509` is added to the web package, bundles under Vite and generates a CSR in the browser pane. If it does not, record why and use PKI.js.
- [ ] A pure web module generates a key pair and CSR for each of the five key algorithms with the chosen signature hash, and imports neither `api.ts` nor `fetch`.
- [ ] A pure web module holds the name rules (DNS only, leading `*.` wildcard, no IPs or underscores, at most 100); the Tools page shows its errors inline.
- [ ] A server test round-trips a generated CSR for each key algorithm through the real `parseCsr`, and pins the web name rules to `normalizeName` on a fixture list.
- [ ] CN is a dropdown of the entered names plus "none", defaulting to the first name. Optional O, OU, C (two letters), ST and L sit in a collapsed section; empty ones are left out.
- [ ] The signature algorithm picker is under "Advanced", offers SHA-256, SHA-384 and SHA-512 for the key's family, defaults as in the spec, and resets on a key-algorithm change unless the choice is still valid. A soft, non-blocking note appears for SHA-256 with P-384.
- [ ] The key (PKCS#8 PEM, behind a "show" toggle with the warning) and the CSR (PEM) each have download and copy buttons; downloaded file names are safe for a wildcard name.
- [ ] A `beforeunload` warning applies while a generated key has not been downloaded or copied, and the key is cleared from state on unmount.
- [ ] The component takes names, key algorithm and whether they are locked as props, so ticket 02 can embed it without changing it.
- [ ] A "Tools" group with a CSR Generator item appears in the Organization sidebar for every Member, with the page at `/organizations/:id/tools/csr`. No server route, permission or Audit Event is added.
- [ ] ADR 0002 gains an addendum, and `CONTEXT.md` a "CSR Generator" entry.
- [ ] Checked in the browser pane: a generated CSR for a wildcard and a plain name, downloaded and decoded with `openssl req -verify`, is valid.

## Comments

The spec's key-strength note covers only SHA-256 with P-384. SHA-256 with RSA is the default and the norm, so noting it would warn on the default choice.

Implemented in the commit "CSR Generator". Still to do before this closes:

- The route `/organizations/:id/tools/csr` (`web/src/router.tsx`) and the "Tools" sidebar group (`web/src/lib/navigation.ts`) are written but left uncommitted: both files carry the unrelated, still uncommitted sidebar rework (`navigation.ts` is untracked, `router.tsx` imports untracked pages). Commit them with that work; they have not been checked in the signed-in app.
- The generator itself was checked in the browser pane through a temporary harness page (wildcard and plain name, `openssl req -verify` OK, safe file names, `beforeunload` lifts after the key is downloaded, soft note for SHA-256 with P-384).
- The CN dropdown offers only names of at most 64 characters (X.520); a longer first name means the CN defaults to none.
- For ticket 02: the component has no output yet (no callback giving the CSR or whether the key is saved), which "Use this CSR" will need.
