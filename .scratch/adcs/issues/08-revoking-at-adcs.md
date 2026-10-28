# 08: Revoking at ADCS

**What to build:** An Owner or Organization Administrator revokes a Certificate from an ADCS CA with an RFC 5280 reason. An Agent carries out `adcs.revoke`, and the Revocation is recorded only once ADCS confirms. A refusal or an unreachable CA is reported and leaves the Certificate unrevoked. A revoked Certificate shows "Revoked" and the CRL Distribution Point URLs read from its own extension, with nothing about when ADCS publishes its CRL. See `.scratch/adcs/spec.md` (Revocation).

**Blocked by:** 02 (revocation recorded on the CA's later confirmation), 06 (TLS Managed Certificates from an ADCS CA).

**Status:** done

- [x] `adcs.revoke` is in the agent contract and implemented on both sides, with `revoked`, `rejected` and `unreachable` results.
- [x] The Revocation and its Audit Event are written only on `revoked`, and the reasons map one-to-one.
- [x] Certificate details show the CDP URLs for every Certificate from an ADCS CA, and "Revoked" once revoked.
- [x] Revoking is allowed after Archive, as for other CAs.
- [x] Seam A tests use the ADCS double. Go: the contract test covers revoke, and Seam B covers `adcs.revoke`.

## Comments

- Server: `adcs-revocation.ts` is the ADCS kind's `revoke`. Each Certificate becomes an `adcs.revoke` work item for the most recently heard-from online assigned Agent, with `configString`, `serialNumber` (lower-case hex) and `reason` (the RFC 5280 code). The Revocation Request (ticket 02) waits for it. The work item also keeps the Revocation Request's id and the Agents tried, but the Agent is not given them. No migration was needed.
- Results: the Agent reports `revocation: { status: "revoked" }`, or fails as `rejected` or `unreachable` (the contract's `kind`). An `unreachable` result passes the item to the next online assigned Agent; once none is left, the request fails as `unreachable`. When no assigned Agent is online at the time of asking, the API answers 502 and records nothing. An Agent that does not report within an hour leaves the request to time out, but a late `revoked` is still recorded. Revoking again is safe because the client contract says an already-revoked Certificate stays revoked.
- Reasons: ADCS takes `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded` and `cessationOfOperation` with the same codes. It has no `privilegeWithdrawn`, which is refused with 422, as other reasons a kind does not take are. The web's reason picker follows `REVOCATION_REASONS_OF.adcs`.
- CDP URLs: Certificate facts gain `crlDistributionPoints`, read from the leaf for every Certificate. The web side sheet lists them under "CRL Distribution Points".
- Go: `Client.Revoke`. The fake records revocations, and the contract's `Manager` gains `RevocationReason` (on a lab host, `certutil -view`). The Agent handles `adcs.revoke`.
