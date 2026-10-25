# 10: List columns repeat the common name and show empty columns

**What to build:** The SANs column repeats the common name ("app.internal.example, api.internal.example"), and Environment tag is blank for Private-CA certificates. Make the columns earn their space.

**Blocked by:** 09

**Status:** done

- [x] Names column: the common name, then the other names muted, or "+N" with a tooltip listing them.
- [x] Environment tag shows "Private" (or the CA name) for a Private-CA certificate, instead of blank.
- [x] Owners shows avatars or names, with "None" in a warning tone (see ticket 13).
