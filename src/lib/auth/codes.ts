import { randomInt } from "node:crypto";
import { cache } from "../cache";
import { blindIndex } from "../crypto";
import { safeEqual } from "../ids";

/**
 * One-time 6-digit codes. Only a keyed HMAC of the code is stored in Valkey, with a
 * 10-minute TTL and at most 5 guesses, after which the code is burned. Issuing a new
 * code replaces the old one. 5 guesses against 10^6 codes ≈ 0.0005% success per code.
 */
const TTL = 600;
const MAX_ATTEMPTS = 5;

type Purpose = "verify_email" | "reset_password" | "org_domain" | "reauth" | "passkey_signup";
const key = (purpose: Purpose, subject: string) => `code:${purpose}:${subject}`;

export async function issueCode(purpose: Purpose, subject: string) {
  const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
  await cache().hset(key(purpose, subject), { h: blindIndex(code, `${purpose}:${subject}`), n: "0" });
  await cache().expire(key(purpose, subject), TTL);
  return code;
}

export async function consumeCode(purpose: Purpose, subject: string, code: string): Promise<boolean> {
  const k = key(purpose, subject);
  const attempts = await cache().hincrby(k, "n", 1);
  const stored = await cache().hget(k, "h");
  if (!stored) {
    await cache().del(k); // hincrby on a missing key created a stub; drop it
    return false;
  }
  if (attempts > MAX_ATTEMPTS) {
    await cache().del(k);
    return false;
  }
  if (!/^\d{6}$/.test(code) || !safeEqual(stored, blindIndex(code, `${purpose}:${subject}`))) return false;
  await cache().del(k); // single use
  return true;
}
