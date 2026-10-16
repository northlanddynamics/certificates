# 07: SCEP hardening and interoperability

**What to build:** The SCEP server copes with the clients and conditions it meets in the field, and a real third-party SCEP client enrolls against it.

**Blocked by:** 02

**Status:** done

- [x] RSA-OAEP key transport, 3DES and (unadvertised) single DES content encryption, and SHA-1-signed requests accepted besides PKCS#1 v1.5 and AES; `GetCACaps` advertises POSTPKIOperation, SHA-256, SHA-512, AES and SCEPStandard, plus Renewal for validators that allow it.
- [x] A repeated transaction ID is answered with its first result without issuing twice; `GetCertInitial` returns the stored result.
- [x] `RenewalReq` is accepted only where the profile's validator allows it.
- [x] Rate limiting per profile and per source address, answered without touching the validator.
- [x] `micromdm/scep`'s client runs in a container in `docker-compose.yml` beside Pebble and BIND, and a test has it enroll against the app and get a certificate.

## Comments

- micromdm's `scepclient` encrypts to every certificate `GetCACert` returns unless run with `-key-encipherment-selector`, and fails when the Issuing CA's key is not RSA. With the selector it encrypts to the RA certificate alone, so the interop test passes it; the platform needs no change for it.
- micromdm publishes no image with the client in it, so `docker/scepclient` builds it from source at v2.3.0.
- Transactions are kept in `scep_transaction` (`server/src/scep-transactions.ts`). Refusals stay there forever for now; ticket 08's pruning should delete them with the profile's retention.
