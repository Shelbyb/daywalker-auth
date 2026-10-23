/**
 * Every database column that holds field-encrypted data, with the context (AAD) each value was
 * encrypted under. MASTER_KEY rotation re-encrypts exactly this list, and a test fails if a
 * `*_enc` column exists in the schema but isn't listed here. Add new encrypted columns below.
 */
export type EncryptedField = {
  table: string;
  column: string;
  /** Primary key columns, used to find the row again. */
  key: string[];
  /** The AAD the app uses for this column. Must match the encrypt() call exactly. */
  context: (row: Record<string, string>) => string;
};

const byId = (table: string, column: string, label = column.replace(/_enc$/, "")): EncryptedField => ({
  table,
  column,
  key: ["id"],
  context: (r) => `${table}.${label}:${r.id}`,
});

export const ENCRYPTED_FIELDS: EncryptedField[] = [
  byId("users", "first_name_enc", "first_name"),
  byId("users", "last_name_enc", "last_name"),
  byId("users", "private_metadata_enc", "private_metadata"),
  byId("email_addresses", "email_enc", "email"),
  byId("sessions", "user_agent_enc", "user_agent"),
  byId("sessions", "ip_address_enc", "ip_address"),
  { table: "oauth_providers", column: "client_secret_enc", key: ["instance_id", "provider"], context: (r) => `oauth_providers.client_secret:${r.instance_id}:${r.provider}` },
  byId("oauth_accounts", "email_enc", "email"),
  { table: "mfa_totp", column: "secret_enc", key: ["user_id"], context: (r) => `mfa_totp.secret:${r.user_id}` },
  { table: "mfa_sms", column: "phone_enc", key: ["user_id"], context: (r) => `mfa_sms.phone:${r.user_id}` },
  byId("saml_connections", "sp_key_enc", "sp_key"),
  byId("instances", "captcha_secret_enc", "captcha_secret"),
  { table: "saml_sessions", column: "name_id_enc", key: ["session_id"], context: (r) => `saml_sessions.name_id:${r.session_id}` },
  { table: "saml_sessions", column: "session_index_enc", key: ["session_id"], context: (r) => `saml_sessions.session_index:${r.session_id}` },
  byId("invitations", "email_enc", "email"),
  byId("signing_keys", "private_key_enc", "private"),
  byId("webhook_endpoints", "url_enc", "url"),
  byId("webhook_endpoints", "secret_enc", "secret"),
  byId("webhook_deliveries", "payload_enc", "payload"),
  byId("audit_events", "data_enc", "data"),
];
