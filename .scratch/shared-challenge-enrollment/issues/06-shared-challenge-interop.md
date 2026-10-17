# 06: Interop: a real SCEP client enrolls with a Shared Challenge

**What to build:** The existing interoperability test, which runs `micromdm/scep`'s client beside the app, also enrolls under a Shared Challenge profile, so a real third-party SCEP client is shown to work with the challenge, including during a rotation.

**Blocked by:** 05

**Status:** done

- [x] The client, given the profile's Shared Challenge, gets a Device Certificate that chains to the root.
- [x] After a rotation, the client enrolls with both the current and the previous challenge.
- [x] A wrong challenge gets a FAILURE the client reports.
