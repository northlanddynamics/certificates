# 06: Managed Certificate in the portal

**What to build:** A portal user opens one of their Managed Certificates and sees its status, expiry and history (requested, approved, issued, renewed). They download the current Certificate by choosing what they are installing it on, renew it now, turn automatic Renewal on or off, and subscribe themselves to its notices.

**Blocked by:** 03 (Sessions land in their front end)

**Status:** ready-for-agent

- [ ] Built on the existing Managed Certificate, export, renewal, Renewal Policy, subscriber and history endpoints; no new server behaviour.
- [ ] The download asks what it is for and picks the format: "Nginx, Apache and most Linux software" gives PEM with the full chain; "Windows, IIS, Java" gives PKCS#7; "Something else" offers the certificate alone, the chain alone, or DER.
- [ ] Renew now, the automatic Renewal toggle and subscribing are offered only when `/api/me` permissions or Ownership allow, and are refused as the API refuses them (for example while a Certificate Profile is disabled).
- [ ] The history shows the Managed Certificate's events in plain words, newest first.
- [ ] Details show names, Owners and key algorithm, and say that the Owner holds the key.
- [ ] A Proposal opens to its state: waiting for Approval, or rejected with its reason.
- [ ] Works at phone width.
