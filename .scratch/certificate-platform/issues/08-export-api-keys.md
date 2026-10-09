# 08: Export formats and API keys

**What to build:** Owners can download the current or any earlier Certificate as PEM, DER or PKCS#7 (P7B), choosing leaf only, leaf plus intermediates, or leaf plus intermediates plus root. Users can create API keys that carry their own permissions, so a CI pipeline can fetch a Certificate in any of these forms.

**Blocked by:** 02 (Members, roles and Teams), 05 (First Certificate (tracer))

**Status:** done

- [x] Downloads are available as PEM, DER and P7B, each with the three chain options.
- [x] Any earlier Certificate of a Managed Certificate can be downloaded.
- [x] No PFX or JKS export exists.
- [x] Users can create and revoke API keys (Better Auth API-key plugin) scoped to their Organization and carrying their permissions.
- [x] An API key can fetch the current Certificate in a chosen format and chain option.
- [x] API key creation, revocation and each use are audited.

## Comments

Implemented on `main`; typecheck, the web build and the full Seam A suite pass against Postgres, Pebble and BIND.

- **Export.** `GET .../managed-certificates/{id}/certificate?format=pem|der|p7b&chain=leaf|with-intermediates|with-root` downloads the current Certificate, and `.../certificates/{certificateId}/download` any earlier one (replacing `certificate.pem`; the defaults, PEM with the intermediates, are what it served). Anything else for `format` or `chain` (PFX, JKS included) is 400. DER is the certificates' DER encodings one after the other (the one Certificate for the leaf alone); P7B is a certificates-only PKCS#7 bundle in PEM armor (`BEGIN PKCS7`), the way CAs hand out `.p7b`. A decision to confirm: DER of a chain has no single standard form, so concatenation was my pick.
- **The root.** A CA serves the leaf and its intermediates, not the root, so `CertificateAuthority` gained `roots(environment)`; an export with the root finds the one that signed the last intermediate (or uses the one the CA served). Let's Encrypt production defaults to the system's trusted roots, which hold ISRG's; staging's roots are in no store, so `createLetsEncrypt({ roots })` takes them, and without a known root `with-root` is 422. Tests read Pebble's root from its management port, which `docker-compose.yml` now publishes (15000).
- **API keys** are Better Auth's `@better-auth/api-key` (new dependency, `apikey` table, migration `0010`). A key belongs to the person who made it, is scoped to one Organization (in its metadata) and carries the permissions that person held there when it was made (a new `managedCertificate: download`, held by every role). Used, it acts as that person: it reaches only its Organization and only what its person may still see and do (a Member's key sees what the Member owns; a person who leaves takes their keys' use with them).
- **What a key opens.** Only the downloads, so far: `callerOf` in `server/src/api-keys.ts` is what a route calls to accept a key too, and every other route takes sessions only (a key gets 401 there, and cannot make or revoke keys). The plugin's own HTTP endpoints are all disabled (`disabledPaths` in `auth.ts`), so keys are made and revoked only through `POST/GET /api/organizations/{orgId}/api-keys` and `DELETE .../{keyId}`, each on the unit of work with its Audit Event. A person lists and revokes only their own keys (not even an Organization Administrator sees another's). The plugin's default of 10 requests a day is raised to 600 an hour; over it a key gets 429.
- **Audited:** `api_key.created` and `api_key.revoked` (the key's name, never its value) and `api_key.used`, written when a download by key is served: actor is the key's person, `detail` has `apiKeyId`, `apiKeyName`, `certificateId`, `format`, `chain`. A request that is refused (bad key, forbidden, no Certificate) leaves none, and downloading signed in is not a use of a key. Leaving the Organization does not delete a person's keys; they stop working, since their person is no longer a member.
- Web: a Download control per Managed Certificate (format, chain and which Certificate, earlier ones included) and an API keys page per Organization that shows a new key once.
- **Review follow-ups.** A banned user's keys stop working too (checked on each use). Known gaps left for later: a key is not deleted when its person leaves the Organization (it stays dead until they are re-added, when it works again; revoke it from the API keys page), and a refused use of a key (bad or expired key, forbidden, 404, 422) leaves no Audit Event. Making keys open more routes than the downloads is for whichever ticket needs them (`callerOf`).
