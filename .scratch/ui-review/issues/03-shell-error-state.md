# 03: A failed /api/me request blanks the whole app

**What to build:** When `/api/me` fails with anything but 401, `components/app-shell.tsx:28` renders only a red "Something went wrong." on a blank page: no sidebar, no retry, no way to sign out. Show a recoverable error instead.

**Blocked by:** none

**Status:** done

- [x] The error state is a centred card saying the platform could not be reached, with Try again (refetches `me`) and Sign out.
- [x] The query retries a few times with backoff before the card shows.
- [x] `managed-certificate-details.tsx:40` and other page-level "Something went wrong." fallbacks get the same card inside the shell, with Try again.
