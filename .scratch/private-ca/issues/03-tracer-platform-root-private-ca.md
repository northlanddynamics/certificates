# 03: Tracer: issue a TLS Certificate from a platform-root Private CA

**What to build:** An Organization Administrator creates a Private CA with a platform-made root and Issuing CA, both keys in the KMS, and downloads its chain. A Managed Certificate with Key Custody: Owner is then created (or proposed and approved) against that Private CA and issued without DCV, and the Certificate verifies to the root. This is the thinnest end-to-end path; name rules, validity, CRL, Renewal and the Organization-root hierarchy come in later tickets. See `spec.md`.

**Blocked by:** 01, 02

**Status:** ready-for-agent

- [ ] An Organization Administrator creates a Private CA with a name, subject DN, key algorithm and lifetime; the platform makes a root and an Issuing CA (pathLen 0) with separate KMS keys, and the Private CA is `active`.
- [ ] Every role can list Private CAs and download a chain (`privateCa.read`); only Organization Administrators hold `privateCa.create` (and the later `update`, `retire`, `revoke`), declared in `permissions.ts` and reported by `/api/me`.
- [ ] Creating or proposing a Managed Certificate accepts a Private CA as its issuer; Approval works exactly as for ACME, and Approvers see which CA it is.
- [ ] Issuance from a Private CA runs no DCV and no ACME order: it signs a TLS server certificate (serverAuth EKU, subject and SANs from the approved names, a 20-byte random serial) through the KMS and stores it with its chain, in the same Unit of Work as its Audit Events, with the existing Issuance states.
- [ ] Downloading the Certificate gives a chain that verifies to the Private CA's root.
- [ ] `private_ca.created` is an Audit Event, and `docs/audit-events.md` documents it; Issuance reuses its existing actions with the issuer in `detail`.
- [ ] Organization isolation: a Managed Certificate in one Organization cannot name another Organization's Private CA.
- [ ] Web: a Private CAs page under the Organization's settings (create, list, download chain) for Organization Administrators, and a CA picker on the Managed Certificate create/propose form.
- [ ] `CONTEXT.md`: Private CA moves out of "future" and is redefined; Issuing CA is added; Certificate Authority and Issuance say DCV applies to ACME CAs only.
- [ ] Tests in the Seam A harness with the local KMS, verifying the chain with `@peculiar/x509`.
