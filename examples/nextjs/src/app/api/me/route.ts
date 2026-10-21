import { auth } from "@daywalker/auth/nextjs";

// Route Handler: accepts the Authorization header or the session cookie.
export async function GET() {
  const session = await auth();
  if (!session.isSignedIn) return Response.json({ error: "unauthenticated" }, { status: 401 });
  return Response.json({ userId: session.userId, sessionId: session.sessionId });
}
