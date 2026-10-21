import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { hash, verify } from "@node-rs/argon2";
import { env } from "./env";

// ---------- Passwords ----------
// OWASP argon2id baseline (19 MiB, t=2, p=1). Hash strings embed params, so raising these later is safe.
const ARGON = { memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;

export const hashPassword = (pw: string) => hash(pw, ARGON);
export const verifyPassword = (digest: string, pw: string) => verify(digest, pw).catch(() => false);

/** Verified against when an account doesn't exist, so timing doesn't reveal which emails are registered. */
let dummy: Promise<string> | undefined;
export const dummyHash = () => (dummy ??= hashPassword(randomBytes(24).toString("hex")));

// ---------- Key hierarchy ----------
// MASTER_KEY never encrypts data directly. Purpose-specific subkeys are derived with HKDF,
// so a bug in one use can't be turned against another.
const KEY_VERSION = "v1";
const subkeys = new Map<string, Buffer>();
function subkey(purpose: "enc" | "index") {
  let k = subkeys.get(purpose);
  if (!k) {
    const master = Buffer.from(env().MASTER_KEY, "base64");
    k = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(0), `daywalker-auth/${KEY_VERSION}/${purpose}`, 32));
    subkeys.set(purpose, k);
  }
  return k;
}

// ---------- Field encryption ----------
/**
 * AES-256-GCM. Output: "v1.<base64(iv|tag|ciphertext)>".
 * `context` is bound as AAD, typically "<table>.<column>:<row id>", so a ciphertext copied
 * into another row or column fails to decrypt instead of silently revealing data.
 */
export function encrypt(plaintext: string, context: string) {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", subkey("enc"), iv);
  c.setAAD(Buffer.from(context));
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  return `${KEY_VERSION}.${Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64")}`;
}

export function decrypt(payload: string, context: string) {
  const [version, body] = payload.split(".", 2);
  if (version !== KEY_VERSION || !body) throw new Error("Unsupported ciphertext version");
  const buf = Buffer.from(body, "base64");
  const d = createDecipheriv("aes-256-gcm", subkey("enc"), buf.subarray(0, 12));
  d.setAAD(Buffer.from(context));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString("utf8");
}

export const encryptNullable = (v: string | null | undefined, ctx: string) => (v ? encrypt(v, ctx) : null);
export const decryptNullable = (v: string | null | undefined, ctx: string) => (v ? decrypt(v, ctx) : null);

/**
 * Keyed blind index (HMAC-SHA256) for exact-match lookups on encrypted fields such as email.
 * Without the key, the index can't be brute-forced from a list of known emails.
 */
export function blindIndex(value: string, purpose: string) {
  return createHmac("sha256", subkey("index")).update(`${purpose}\0${value}`).digest("hex");
}
