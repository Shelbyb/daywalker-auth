import {
  pgTable,
  text,
  timestamp,
  boolean,
  jsonb,
  uniqueIndex,
  index,
  pgEnum,
} from "drizzle-orm/pg-core";

// Prefixed, sortable-enough IDs are generated in app code (see lib/ids.ts).
const id = (name = "id") => text(name).primaryKey();
const createdAt = () => timestamp("created_at", { withTimezone: true }).notNull().defaultNow();
const updatedAt = () => timestamp("updated_at", { withTimezone: true }).notNull().defaultNow();

/** A developer account that owns applications (dashboard users). */
export const accounts = pgTable("accounts", {
  id: id(),
  name: text("name").notNull(),
  createdAt: createdAt(),
});

export const environmentEnum = pgEnum("environment", ["development", "production"]);

/** An application environment. Every end-user record is scoped to one instance. */
export const instances = pgTable(
  "instances",
  {
    id: id(),
    accountId: text("account_id").notNull().references(() => accounts.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    environment: environmentEnum("environment").notNull().default("development"),
    // Origins allowed to call the frontend API with credentials (CORS).
    allowedOrigins: jsonb("allowed_origins").$type<string[]>().notNull().default([]),
    settings: jsonb("settings")
      .$type<{ passwordMinLength: number; sessionLifetimeDays: number; tokenTtlSeconds: number }>()
      .notNull()
      .default({ passwordMinLength: 8, sessionLifetimeDays: 7, tokenTtlSeconds: 60 }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [index("instances_account_idx").on(t.accountId)],
);

/** Secret keys for the backend API. Only a hash is stored. */
export const apiKeys = pgTable(
  "api_keys",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    keyHash: text("key_hash").notNull(),
    keyPrefix: text("key_prefix").notNull(), // first chars, for display
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex("api_keys_hash_idx").on(t.keyHash)],
);

/** Per-instance JWT signing keys. Private key is AES-GCM encrypted with MASTER_KEY. */
export const signingKeys = pgTable(
  "signing_keys",
  {
    id: id(), // used as JWT `kid`
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    alg: text("alg").notNull().default("ES256"),
    publicJwk: jsonb("public_jwk").$type<Record<string, unknown>>().notNull(),
    privateKeyEnc: text("private_key_enc").notNull(),
    active: boolean("active").notNull().default(true),
    retiredAt: timestamp("retired_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [index("signing_keys_instance_idx").on(t.instanceId)],
);

/** End users of a customer's application. */
export const users = pgTable(
  "users",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    // PII columns hold AES-GCM ciphertext (see lib/crypto.ts), bound to the row ID.
    firstNameEnc: text("first_name_enc"),
    lastNameEnc: text("last_name_enc"),
    imageUrl: text("image_url"),
    publicMetadata: jsonb("public_metadata").$type<Record<string, unknown>>().notNull().default({}),
    privateMetadataEnc: text("private_metadata_enc"), // encrypted JSON
    banned: boolean("banned").notNull().default(false),
    lastSignInAt: timestamp("last_sign_in_at", { withTimezone: true }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [index("users_instance_idx").on(t.instanceId)],
);

export const emailAddresses = pgTable(
  "email_addresses",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    emailEnc: text("email_enc").notNull(), // ciphertext of the normalized email
    emailIndex: text("email_index").notNull(), // keyed HMAC blind index for lookups
    isPrimary: boolean("is_primary").notNull().default(false),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex("email_addresses_instance_email_idx").on(t.instanceId, t.emailIndex),
    index("email_addresses_user_idx").on(t.userId),
  ],
);

/** Kept separate from users so password hashes never ride along on user reads. */
export const passwords = pgTable("passwords", {
  userId: text("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  hash: text("hash").notNull(),
  updatedAt: updatedAt(),
});

export const sessionStatusEnum = pgEnum("session_status", ["active", "ended", "revoked", "expired"]);

/**
 * A signed-in session. The browser holds an opaque refresh token in an httpOnly
 * cookie (we store only its hash) and exchanges it for short-lived JWTs.
 */
export const sessions = pgTable(
  "sessions",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    refreshTokenHash: text("refresh_token_hash").notNull(),
    status: sessionStatusEnum("status").notNull().default("active"),
    userAgentEnc: text("user_agent_enc"),
    ipAddressEnc: text("ip_address_enc"),
    lastActiveAt: timestamp("last_active_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex("sessions_refresh_hash_idx").on(t.refreshTokenHash),
    index("sessions_user_idx").on(t.userId),
  ],
);

export type Instance = typeof instances.$inferSelect;
export type User = typeof users.$inferSelect;
export type Session = typeof sessions.$inferSelect;

export const oauthProviderEnum = pgEnum("oauth_provider", ["google", "github"]);

/** Per-instance OAuth app credentials. The client secret is encrypted (AAD-bound to instance+provider). */
export const oauthProviders = pgTable(
  "oauth_providers",
  {
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    provider: oauthProviderEnum("provider").notNull(),
    clientId: text("client_id").notNull(),
    clientSecretEnc: text("client_secret_enc").notNull(),
    enabled: boolean("enabled").notNull().default(true),
    updatedAt: updatedAt(),
  },
  (t) => [uniqueIndex("oauth_providers_pk").on(t.instanceId, t.provider)],
);

/** A user's linked external identity. The provider's user ID is stored only as a blind index. */
export const oauthAccounts = pgTable(
  "oauth_accounts",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    provider: oauthProviderEnum("provider").notNull(),
    providerUserIndex: text("provider_user_index").notNull(),
    emailEnc: text("email_enc"),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex("oauth_accounts_identity_idx").on(t.instanceId, t.provider, t.providerUserIndex),
    index("oauth_accounts_user_idx").on(t.userId),
  ],
);

/** Authenticator-app secret. Encrypted; `verifiedAt` is null until the user confirms a first code. */
export const mfaTotp = pgTable("mfa_totp", {
  userId: text("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  secretEnc: text("secret_enc").notNull(),
  verifiedAt: timestamp("verified_at", { withTimezone: true }),
  createdAt: createdAt(),
});

/** One-time recovery codes. Only keyed hashes are stored. */
export const backupCodes = pgTable(
  "backup_codes",
  {
    id: id(),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    codeHash: text("code_hash").notNull(),
    usedAt: timestamp("used_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex("backup_codes_user_hash_idx").on(t.userId, t.codeHash)],
);
