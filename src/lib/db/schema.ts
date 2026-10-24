import {
  pgTable,
  text,
  timestamp,
  boolean,
  jsonb,
  uniqueIndex,
  index,
  pgEnum,
  bigint,
  primaryKey,
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

/** Which dashboard users (people signed in to the platform instance) can manage an account's instances. */
export const accountMembers = pgTable(
  "account_members",
  {
    accountId: text("account_id").notNull().references(() => accounts.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull(), // a user of the platform instance
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex("account_members_pk").on(t.accountId, t.userId), index("account_members_user_idx").on(t.userId)],
);

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
    /** Cloudflare Turnstile secret, encrypted. */
    captchaSecretEnc: text("captcha_secret_enc"),
    settings: jsonb("settings")
      .$type<{ passwordMinLength: number; sessionLifetimeDays: number; tokenTtlSeconds: number; emailCodeSignIn?: boolean; breachedPasswordCheck?: boolean; emailAccentColor?: string; smsSecondFactor?: boolean; smsCountries?: string[];
        /** Sign-up rules for new accounts (see auth/signup-protection.ts). */
        signUpAllowedDomains?: string[]; signUpBlockedDomains?: string[]; blockDisposableEmails?: boolean;
        /** Cloudflare Turnstile site key; the secret is in captcha_secret_enc. */
        captchaSiteKey?: string | null;
        /** Two-factor policy: required for everyone, after a grace period that ends at this time. */
        requireTwoFactor?: boolean; twoFactorGraceUntil?: string | null;
        /** Hosted page look: logo, colors, heading. */
        branding?: { logoUrl?: string | null; primaryColor?: string | null; backgroundColor?: string | null; title?: string | null };
        /** Account Portal fallbacks when no redirect_url is given; checked against allowed origins when used. */
        redirects?: { afterSignIn?: string | null; afterSignUp?: string | null; afterLogoClick?: string | null } }>()
      .notNull()
      .default({ passwordMinLength: 8, sessionLifetimeDays: 7, tokenTtlSeconds: 60 }),
    // Terms new users must accept. `version` is recorded with each acceptance.
    legal: jsonb("legal")
      .$type<{ required: boolean; termsUrl: string | null; privacyUrl: string | null; version: string }>()
      .notNull()
      .default({ required: false, termsUrl: null, privacyUrl: null, version: "1" }),
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
    activeOrgId: text("active_org_id"), // carried in the JWT as org_id/org_role
    /** Set when a platform staff member opened this session by impersonating the user (a platform-instance user ID). */
    impersonatorId: text("impersonator_id"),
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

export const oauthProviderEnum = pgEnum("oauth_provider", ["google", "github", "microsoft", "apple", "discord", "gitlab", "oidc", "saml"]);

/** Per-instance OAuth app credentials. The client secret is encrypted (AAD-bound to instance+provider). */
export const oauthProviders = pgTable(
  "oauth_providers",
  {
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    provider: oauthProviderEnum("provider").notNull(),
    clientId: text("client_id").notNull(),
    clientSecretEnc: text("client_secret_enc").notNull(),
    enabled: boolean("enabled").notNull().default(true),
    /** Non-secret per-provider options (OIDC issuer, Microsoft tenant, Apple team and key IDs). */
    settings: jsonb("settings").$type<import("../auth/oauth-providers").ProviderSettings>().notNull().default({}),
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

/** A phone number used for SMS two-factor. Encrypted; the blind index only feeds per-number rate limits. */
export const mfaSms = pgTable("mfa_sms", {
  userId: text("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  phoneEnc: text("phone_enc").notNull(),
  phoneIndex: text("phone_index").notNull(),
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

/**
 * WebAuthn passkeys. Only the public key is stored: the private key never leaves the
 * user's device. Credential IDs are public identifiers, not secrets.
 */
export const passkeys = pgTable(
  "passkeys",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    credentialId: text("credential_id").notNull(), // base64url
    publicKey: text("public_key").notNull(), // base64url COSE key
    counter: bigint("counter", { mode: "number" }).notNull().default(0),
    transports: jsonb("transports").$type<string[]>().notNull().default([]),
    deviceType: text("device_type").notNull(), // "singleDevice" | "multiDevice" (synced)
    backedUp: boolean("backed_up").notNull().default(false),
    name: text("name").notNull(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex("passkeys_instance_credential_idx").on(t.instanceId, t.credentialId),
    index("passkeys_user_idx").on(t.userId),
  ],
);

/**
 * Security keys registered as a *second* factor. Kept apart from `passkeys` on purpose: a passkey can
 * sign someone in on its own, a security key never can.
 */
export const mfaSecurityKeys = pgTable(
  "mfa_security_keys",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    credentialId: text("credential_id").notNull(), // base64url
    publicKey: text("public_key").notNull(), // base64url COSE key
    counter: bigint("counter", { mode: "number" }).notNull().default(0),
    transports: jsonb("transports").$type<string[]>().notNull().default([]),
    name: text("name").notNull(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex("mfa_security_keys_instance_credential_idx").on(t.instanceId, t.credentialId),
    index("mfa_security_keys_user_idx").on(t.userId),
  ],
);

/** Proof that a user accepted a given version of the instance's terms, and when. */
export const legalAcceptances = pgTable(
  "legal_acceptances",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    version: text("version").notNull(),
    method: text("method").notNull(), // "password" or a provider name
    acceptedAt: timestamp("accepted_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("legal_acceptances_user_idx").on(t.userId)],
);

export const orgRoleEnum = pgEnum("org_role", ["admin", "member"]);

export const organizations = pgTable(
  "organizations",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    slug: text("slug").notNull(),
    /** Members must have two-factor on to use this organization (no org claims in their token otherwise). */
    requireTwoFactor: boolean("require_two_factor").notNull().default(false),
    createdBy: text("created_by"),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex("organizations_instance_slug_idx").on(t.instanceId, t.slug)],
);

export const memberships = pgTable(
  "memberships",
  {
    orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    role: orgRoleEnum("role").notNull().default("member"),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex("memberships_org_user_idx").on(t.orgId, t.userId), index("memberships_user_idx").on(t.userId)],
);

/** Email invitations. The link token is stored hashed; the email encrypted with a blind index. */
export const invitations = pgTable(
  "invitations",
  {
    id: id(),
    orgId: text("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
    emailEnc: text("email_enc").notNull(),
    emailIndex: text("email_index").notNull(),
    role: orgRoleEnum("role").notNull().default("member"),
    tokenHash: text("token_hash").notNull(),
    invitedBy: text("invited_by"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    acceptedAt: timestamp("accepted_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex("invitations_token_idx").on(t.tokenHash), index("invitations_org_idx").on(t.orgId)],
);

/**
 * A URL we POST signed events to. The URL and signing secret are encrypted at rest (a URL can
 * embed a token, and we need the secret back to sign payloads).
 */
export const webhookEndpoints = pgTable(
  "webhook_endpoints",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    urlEnc: text("url_enc").notNull(),
    secretEnc: text("secret_enc").notNull(),
    events: jsonb("events").$type<string[]>().notNull().default(["*"]),
    description: text("description"),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: createdAt(),
  },
  (t) => [index("webhook_endpoints_instance_idx").on(t.instanceId)],
);

export const webhookStatusEnum = pgEnum("webhook_status", ["pending", "succeeded", "failed"]);

/** One event queued for one endpoint, with its retry state. The payload is encrypted (it holds user data). */
export const webhookDeliveries = pgTable(
  "webhook_deliveries",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    endpointId: text("endpoint_id").notNull().references(() => webhookEndpoints.id, { onDelete: "cascade" }),
    eventId: text("event_id").notNull(),
    eventType: text("event_type").notNull(),
    payloadEnc: text("payload_enc").notNull(),
    status: webhookStatusEnum("status").notNull().default("pending"),
    attempts: bigint("attempts", { mode: "number" }).notNull().default(0),
    nextAttemptAt: timestamp("next_attempt_at", { withTimezone: true }).notNull().defaultNow(),
    lastStatusCode: bigint("last_status_code", { mode: "number" }),
    lastError: text("last_error"),
    deliveredAt: timestamp("delivered_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [
    index("webhook_deliveries_due_idx").on(t.status, t.nextAttemptAt),
    index("webhook_deliveries_endpoint_idx").on(t.endpointId, t.createdAt),
  ],
);

/**
 * An append-only record of what happened in an instance: sign-ins, security changes, settings and
 * key changes. `type`, actor and target are plaintext so they can be filtered; anything that could
 * identify a person (emails, names) goes in `data_enc`.
 */
export const auditEvents = pgTable(
  "audit_events",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    type: text("type").notNull(),
    /** "user" (an end user), "developer" (dashboard), "api" (secret key) or "system". */
    actorType: text("actor_type").notNull(),
    actorId: text("actor_id"),
    targetId: text("target_id"),
    dataEnc: text("data_enc"),
    createdAt: createdAt(),
  },
  (t) => [
    index("audit_events_instance_idx").on(t.instanceId, t.createdAt),
    index("audit_events_type_idx").on(t.instanceId, t.type, t.createdAt),
    index("audit_events_target_idx").on(t.instanceId, t.targetId, t.createdAt),
  ],
);

/** A developer's wording for one kind of email. Missing row = the built-in default. */
export const emailTemplates = pgTable(
  "email_templates",
  {
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(),
    subject: text("subject").notNull(),
    body: text("body").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.instanceId, t.kind] })],
);

/**
 * Enterprise SSO: one SAML identity provider (Okta, Entra ID, Google Workspace…). Certificates are
 * public, so they're stored as-is. People whose email is at one of `domains` sign in through it.
 */
export const samlConnections = pgTable(
  "saml_connections",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    /** New users signing in through this connection join this organization. */
    orgId: text("org_id").references(() => organizations.id, { onDelete: "set null" }),
    idpEntityId: text("idp_entity_id").notNull(),
    ssoUrl: text("sso_url").notNull(),
    certificates: jsonb("certificates").$type<string[]>().notNull(),
    enabled: boolean("enabled").notNull().default(true),
    /** When true, people at this connection's domains can only sign in through the identity provider. */
    ssoRequired: boolean("sso_required").notNull().default(false),
    /** SCIM provisioning bearer token: only its SHA-256 is stored. Null means provisioning is off. */
    scimTokenHash: text("scim_token_hash"),
    scimTokenPrefix: text("scim_token_prefix"),
    scimTokenCreatedAt: timestamp("scim_token_created_at", { withTimezone: true }),
    // SCIM group names (lowercased) whose members become admins of the connection's organization. Empty: roles are left alone.
    scimAdminGroups: jsonb("scim_admin_groups").$type<string[]>().notNull().default([]),
    /** The identity provider's single logout URL (HTTP-Redirect). */
    sloUrl: text("slo_url"),
    /** When true, signing out of the app also signs the person out at the identity provider. */
    singleLogout: boolean("single_logout").notNull().default(false),
    /** Our signing key for logout messages, created on first use: private key encrypted, certificate public. */
    spKeyEnc: text("sp_key_enc"),
    spCert: text("sp_cert"),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [index("saml_connections_instance_idx").on(t.instanceId)],
);

/** Users a connection's SCIM provisioning manages (created by it, or adopted from its domains). */
export const scimUsers = pgTable(
  "scim_users",
  {
    connectionId: text("connection_id").notNull().references(() => samlConnections.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    externalId: text("external_id"),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex("scim_users_connection_user_idx").on(t.connectionId, t.userId), index("scim_users_user_idx").on(t.userId)],
);

/** Which SAML sign-in a session came from, so either side can end it (single logout). NameID encrypted, blind-indexed. */
export const samlSessions = pgTable(
  "saml_sessions",
  {
    sessionId: text("session_id").primaryKey().references(() => sessions.id, { onDelete: "cascade" }),
    connectionId: text("connection_id").notNull().references(() => samlConnections.id, { onDelete: "cascade" }),
    nameIdEnc: text("name_id_enc").notNull(),
    nameIdIndex: text("name_id_index").notNull(),
    nameIdFormat: text("name_id_format"),
    sessionIndexEnc: text("session_index_enc"),
    createdAt: createdAt(),
  },
  (t) => [index("saml_sessions_name_idx").on(t.connectionId, t.nameIdIndex)],
);

/** Groups pushed by the identity provider (SCIM). Names are matched against a connection's admin groups. */
export const scimGroups = pgTable(
  "scim_groups",
  {
    id: id(),
    connectionId: text("connection_id").notNull().references(() => samlConnections.id, { onDelete: "cascade" }),
    displayName: text("display_name").notNull(),
    externalId: text("external_id"),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex("scim_groups_connection_name_idx").on(t.connectionId, t.displayName)],
);

export const scimGroupMembers = pgTable(
  "scim_group_members",
  {
    groupId: text("group_id").notNull().references(() => scimGroups.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  },
  (t) => [primaryKey({ columns: [t.groupId, t.userId] }), index("scim_group_members_user_idx").on(t.userId)],
);

export const platformRoleEnum = pgEnum("platform_role", ["admin", "user"]);

/**
 * Operators of the whole service (people signed in to the platform instance). "admin" can do
 * everything, including platform settings and managing staff; "user" can see every instance,
 * the analytics and the platform audit log, and impersonate.
 */
export const platformStaff = pgTable("platform_staff", {
  userId: text("user_id").primaryKey(), // a user of the platform instance
  role: platformRoleEnum("role").notNull().default("user"),
  createdBy: text("created_by"),
  createdAt: createdAt(),
});

/**
 * What platform staff did: impersonation, settings and staff changes. Never shown to customers.
 * Instance-independent; details (reason, emails, IP) are encrypted.
 */
export const platformAuditEvents = pgTable(
  "platform_audit_events",
  {
    id: id(),
    type: text("type").notNull(),
    actorId: text("actor_id"),
    instanceId: text("instance_id"),
    targetId: text("target_id"),
    dataEnc: text("data_enc"),
    createdAt: createdAt(),
  },
  (t) => [index("platform_audit_created_idx").on(t.createdAt), index("platform_audit_type_idx").on(t.type, t.createdAt)],
);

/** Settings the whole platform uses (one row, id "default"). Secrets are encrypted; unset fields fall back to env. */
export const platformSettings = pgTable("platform_settings", {
  id: id(),
  mailFrom: text("mail_from"),
  resendApiKeyEnc: text("resend_api_key_enc"),
  twilioAccountSid: text("twilio_account_sid"),
  twilioAuthTokenEnc: text("twilio_auth_token_enc"),
  twilioVerifyServiceSid: text("twilio_verify_service_sid"),
  updatedBy: text("updated_by"),
  updatedAt: updatedAt(),
});

/** Each email domain routes to at most one connection per instance. */
export const samlDomains = pgTable(
  "saml_domains",
  {
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    domain: text("domain").notNull(),
    connectionId: text("connection_id").notNull().references(() => samlConnections.id, { onDelete: "cascade" }),
  },
  (t) => [primaryKey({ columns: [t.instanceId, t.domain] }), index("saml_domains_connection_idx").on(t.connectionId)],
);

/** Custom hostnames for an instance's hosted pages. Active only once its DNS CNAME is verified. */
export const customDomains = pgTable(
  "custom_domains",
  {
    id: id(),
    instanceId: text("instance_id").notNull().references(() => instances.id, { onDelete: "cascade" }),
    hostname: text("hostname").notNull(),
    verifyToken: text("verify_token").notNull(),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex("custom_domains_hostname_idx").on(t.hostname), index("custom_domains_instance_idx").on(t.instanceId)],
);
