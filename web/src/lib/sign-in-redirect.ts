// Where sign-in sends someone back to: the page they asked for when signed out. Pure and free of the app's imports, so the
// server's tests can run it.

/**
 * The path to go back to after signing in, when `redirect` is a path on this origin; "/" for anything else (another
 * origin, a protocol-relative `//host`, a backslash trick or junk), so the parameter cannot send anyone off the platform.
 */
export function safeRedirect(redirect: unknown, origin: string): string {
  if (typeof redirect !== "string" || !redirect.startsWith("/") || redirect.startsWith("//") || redirect.includes("\\")) return "/";
  try {
    const url = new URL(redirect, origin);
    if (url.origin !== origin) return "/";
    // Back to sign-in would only ask again.
    if (url.pathname === "/sign-in") return "/";
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return "/";
  }
}
