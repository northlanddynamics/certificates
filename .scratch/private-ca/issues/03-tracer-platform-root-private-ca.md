# 03: Tracer: issue a TLS Certificate from a platform-root Private CA

**What to build:** An Organization Administrator creates a Private CA with a platform-made root and Issuing CA, both keys in the KMS, and downloads its chain. A Managed Certificate with Key Custody: Owner is then created (or proposed and approved) against that Private CA and issued without DCV, and the Certificate verifies to the root. This is the thinnest end-to-end path; name rules, validity, CRL, Renewal and the Organization-root hierarchy come in later tickets. See `spec.md`.

**Blocked by:** 01, 02

**Status:** done

- [x] An Organization Administrator creates a Private CA with a name, subject DN, key algorithm and lifetime; the platform makes a root and an Issuing CA (pathLen 0) with separate KMS keys, and the Private CA is `active`.
- [x] Every role can list Private CAs and download a chain (`privateCa.read`); only Organization Administrators hold `privateCa.create` (and the later `update`, `retire`, `revoke`), declared in `permissions.ts` and reported by `/api/me`.
- [x] Creating or proposing a Managed Certificate accepts a Private CA as its issuer; Approval works exactly as for ACME, and Approvers see which CA it is.
- [x] Issuance from a Private CA runs no DCV and no ACME order: it signs a TLS server certificate (serverAuth EKU, subject and SANs from the approved names, a 20-byte random serial) through the KMS and stores it with its chain, in the same Unit of Work as its Audit Events, with the existing Issuance states.
- [x] Downloading the Certificate gives a chain that verifies to the Private CA's root.
- [x] `private_ca.created` is an Audit Event, and `docs/audit-events.md` documents it; Issuance reuses its existing actions with the issuer in `detail`.
- [x] Organization isolation: a Managed Certificate in one Organization cannot name another Organization's Private CA.
- [x] Web: a Private CAs page under the Organization's settings (create, list, download chain) for Organization Administrators, and a CA picker on the Managed Certificate create/propose form.
- [x] `CONTEXT.md`: Private CA moves out of "future" and is redefined; Issuing CA is added; Certificate Authority and Issuance say DCV applies to ACME CAs only.
- [x] Tests in the Seam A harness with the local KMS, verifying the chain with `@peculiar/x509`.

## Comments

Implemented. Notes for the tickets that follow:

- `server/src/private-ca.ts` holds the routes and `createPrivateCas` (what the Private CA kind of issuer signs through); `server/src/ca-certificates.ts` is the CA module (profiles, serials, a KMS-backed signer for `@peculiar/x509`). Tests: `server/test/private-ca.test.ts`.
- A Private CA's `lifetimeYears` applies to both the root and the Issuing CA. A TLS Certificate gets 397 days, clipped to the Issuing CA's `notAfter`; ticket 05 makes this configurable.
- No CDP or AIA yet (ticket 06). Revoking a Private CA Certificate is refused with 422 until ticket 06.
- Only Key Custody: Owner is offered a Private CA; Deployments (Agent custody) stay ACME until ticket 08.
- `issuance.failed` does not carry `detail.issuer`; `issuance.started` of the same Issuance does.
