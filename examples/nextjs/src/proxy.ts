import { authProxy } from "@daywalker/auth/nextjs";

// Signed-out visitors to these routes are sent to sign-in (pages) or get a 401 (API).
export default authProxy({ protect: ["/dashboard*", "/api/me"] });

export const config = { matcher: ["/((?!_next|favicon.ico).*)"] };
