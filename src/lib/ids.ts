import { randomBytes, createHash, timingSafeEqual } from "node:crypto";

const ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";

/** Prefixed random ID, e.g. user_k3j9..., 22 chars of entropy (~113 bits). */
export function newId(prefix: "acct" | "ins" | "key" | "sk" | "user" | "email" | "sess" | "oa" | "bc" | "pk" | "la" | "org" | "inv" | "we" | "wd" | "evt" | "wh" | "aud" | "paud" | "saml" | "sg" | "dom" | "plan" | "app") {
  const bytes = randomBytes(22);
  let out = "";
  for (const b of bytes) out += ALPHABET[b % 36];
  return `${prefix}_${out}`;
}

/** High-entropy opaque token (refresh tokens, secret keys). */
export function newToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function sha256(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

export function safeEqual(a: string, b: string) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
