/**
 * Post-sign-in redirects are allowed only to a relative path on this service or to an
 * http(s) URL whose origin is on the instance's allow-list. Anything else is dropped,
 * so hosted pages can't be abused as an open redirect for phishing.
 */
export function safeRedirect(value: string | undefined, allowedOrigins: string[]): string | null {
  if (!value || value.length > 2048) return null;
  if (value.startsWith("/") && !value.startsWith("//") && !value.includes("\\")) return value;
  try {
    const u = new URL(value);
    if ((u.protocol === "https:" || u.protocol === "http:") && allowedOrigins.includes(u.origin)) return u.toString();
  } catch {}
  return null;
}
