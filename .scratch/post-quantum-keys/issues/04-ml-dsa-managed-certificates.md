# 04: ML-DSA Managed Certificates with Owner custody

**What to build:** A Managed Certificate issued from an ML-DSA Private CA may have an ML-DSA-44, -65 or -87 key, from a pasted CSR; anywhere else ML-DSA is refused. See `spec.md`, "Where each is allowed".

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] `parseCsr` recognises ML-DSA CSRs; its error messages list the supported algorithms.
- [ ] Creating a Managed Certificate, a Name Change and a Renewal CSR refuse an ML-DSA key algorithm on an ACME CA or an RSA/ECDSA Private CA, and an RSA/ECDSA key algorithm on an ML-DSA Private CA, each with a 422 saying why. Scenarios cover each.
- [ ] Inventory filters, the Managed Certificate details and the new Managed Certificate dialog show the ML-DSA algorithms, offered only for an ML-DSA Private CA.
- [ ] The API that lists the CAs a Managed Certificate can be issued from says which key algorithms each takes, so the web does not hard-code the rule.
