# 08: Renewal and Agent custody from a Private CA

**What to build:** Managed Certificates on a Private CA renew on their Renewal Policy (there is no ARI), and Key Custody: Agent works for them, so a Deployment can install a Private CA Certificate exactly as it installs a public one.

**Blocked by:** 03

**Status:** done

- [x] The Renewal scheduler renews automatic Managed Certificates on a Private CA by days before expiry and the tenth-of-life rule alone; it asks the Private CA no ARI.
- [x] Manual Renewal and a Renewal after a Name Change work as for ACME.
- [x] A Deployment with an Agent holding the key obtains and deploys a Private CA Certificate with its full chain, in a scenario like the first-Deployment test.

## Comments

- The Agent path itself needed no change, but setting up a Deployment did: `POST /deployments` took only an ACME `environment`. It now takes `issuer` and `validityDays` as Managed Certificate create does (the same check, `issuerAsked` in `private-ca.ts`), and the web's Deployment dialog offers the same Issuing CA choice as the Managed Certificate dialog (`components/issuer-choice.tsx`).
- The scheduler no longer asks a Private CA about renewal windows at all (`Issuers.renewalInfoKinds`), so a Private CA Certificate's `renewal.ari` stays null instead of showing an empty answer the CA never gave.
