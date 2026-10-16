# 07: SCEP hardening and interoperability

**What to build:** The SCEP server copes with the clients and conditions it meets in the field, and a real third-party SCEP client enrolls against it.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] RSA-OAEP key transport, 3DES and (unadvertised) single DES content encryption, and SHA-1-signed requests accepted besides PKCS#1 v1.5 and AES; `GetCACaps` advertises POSTPKIOperation, SHA-256, SHA-512, AES and SCEPStandard, plus Renewal for validators that allow it.
- [ ] A repeated transaction ID is answered with its first result without issuing twice; `GetCertInitial` returns the stored result.
- [ ] `RenewalReq` is accepted only where the profile's validator allows it.
- [ ] Rate limiting per profile and per source address, answered without touching the validator.
- [ ] `micromdm/scep`'s client runs in a container in `docker-compose.yml` beside Pebble and BIND, and a test has it enroll against the app and get a certificate.
