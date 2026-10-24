# 14: The issuer is shown three different ways

**What to build:** On a Private-CA certificate the header says "Acme Internal TLS (Private CA Internal TLS)", Current Certificate says "Issued by CN=Acme Internal TLS, O=Acme", and then "CA: Internal TLS". Pick one way to name an issuer and use it everywhere.

**Blocked by:** none

**Status:** done

- [x] One helper formats an issuer as "<Issuing CA> · <Private CA>" or "<ACME CA>", used by the header, Overview, the list and the wizard.
- [x] Current Certificate keeps the full Issuer DN as a secondary, monospace line.
- [x] The CA name links to the Private CAs or ACME accounts page for those who may open it.
