export { createAuthClient, AuthError, type AuthClient, type AuthState, type SignInResult, type OAuthProvider, type OrgInfo, type Reauth, type ReauthRequirements, type SessionInfo, type SecurityInfo, type SecurityKeyInfo, type PasskeyInfo, type ReverificationNeed, type ReverificationOptions, type User, type EmailAddress } from "./client";
export { instanceIdFromKey, issuerFor, SESSION_COOKIE, ACTIVE_COOKIE, type Config } from "./keys";
export { createDpopProof, generateDeviceKey, indexedDbKeyStore, deviceKeysSupported, type DeviceKey, type DeviceKeyStore } from "./dpop";
export { isRecentlyVerified, staleFactors, type ReverificationLevel, type RecentAuthCheck } from "./fresh";

export { TEST_CODE, TEST_EMAIL_TAG, testEmail, testPhone, isTestEmail, isTestPhone } from "./testing";
export { SATELLITE_SYNC_PATH, SATELLITE_HANDSHAKE_PATH, assertSatelliteConfig, buildSyncUrl, safeReturnTarget } from "./satellite";
