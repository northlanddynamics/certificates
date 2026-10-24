# 02: Dark theme never applies

**What to build:** `web/src/index.css` defines a `.dark` theme, but nothing sets the class, so the app is always light, even when the OS prefers dark. `components/ui/sonner.tsx` calls `useTheme()` from next-themes with no `ThemeProvider` above it. Add the provider and a way to choose the theme.

**Blocked by:** none

**Status:** ready-for-agent

- [ ] A next-themes `ThemeProvider` (`attribute="class"`, `defaultTheme="system"`) wraps the root route, so the public pages follow it too.
- [ ] The user menu offers Light, Dark and System.
- [ ] Every page, dialog, badge and the Lifecycle bar is checked in dark; colours hard-coded outside the theme tokens are fixed.
- [ ] Toasts follow the theme.
