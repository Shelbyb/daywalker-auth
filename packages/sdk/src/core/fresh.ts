/** Step-up checks shared by the browser prompt and the server helpers. Safe in any runtime. */

/**
 * Step-up authentication. `first_factor`: the person proved a password, passkey or emailed code recently.
 * `second_factor`: they proved an authenticator, text, security key or backup code recently.
 * `multi_factor`: both (a user-verified passkey counts as both).
 */
export type ReverificationLevel = "first_factor" | "second_factor" | "multi_factor";
export type RecentAuthCheck = { /** Seconds. How recently the person must have proved themselves. */ maxAge: number; /** Default `first_factor`. */ level?: ReverificationLevel };

/** Which of the two factors is too old (or never proved) for this check. Both false = satisfied. */
export function staleFactors(claims: { fva?: [number, number]; issuedAt: number } | null | undefined, check: RecentAuthCheck, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!claims?.fva || !Number.isFinite(check.maxAge) || check.maxAge < 0) return { first: true, second: true };
  const sinceIssue = Math.max(0, nowSeconds - claims.issuedAt);
  const fresh = (age: number) => age >= 0 && age + sinceIssue <= check.maxAge;
  const level = check.level ?? "first_factor";
  const [first, second] = claims.fva;
  return { first: level !== "second_factor" && !fresh(first), second: level !== "first_factor" && !fresh(second) };
}

/**
 * Has the person proved themselves recently enough? Ages are measured now: the token's `fva` (age when it was
 * issued) plus the time since issue, so an old token can't look fresh. False for signed-out and for tokens from
 * sessions that never proved the requested factor (for example `second_factor` for an account with no two-factor).
 */
export function isRecentlyVerified(claims: { fva?: [number, number]; issuedAt: number } | null | undefined, check: RecentAuthCheck, nowSeconds?: number): boolean {
  const s = staleFactors(claims, check, nowSeconds);
  return !s.first && !s.second;
}
