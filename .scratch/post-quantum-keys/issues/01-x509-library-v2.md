# 01: Move to X.509 library v2

**What to build:** The server and the web app run on version 2 of the X.509 library with no change in behaviour, so that ML-DSA CSRs, Certificates and CRLs can later be parsed and verified (version 1.14.3 cannot verify an ML-DSA signature; 2.2.0 can). See `spec.md`, "X.509 library".

**Blocked by:** None (can start immediately)

**Status:** done

- [x] The server and the web app pin the same 2.x version.
- [x] The reflection polyfill version 2 needs is loaded before the library everywhere it loads: the server, its tests, and the web app.
- [x] The override of the ASN.1 schema package in the root package manifest is kept, changed or removed, with the reason in the commit message.
- [x] Typecheck, the server tests and the web build pass unchanged.
