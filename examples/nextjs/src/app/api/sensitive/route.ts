import { auth, ReverificationRequiredError } from "@daywalker/auth/nextjs";

// A sensitive action: the person must have proved themselves in the last 5 minutes.
// When they haven't, answer 403 reverification_required: the browser SDK shows its prompt and retries.
export async function POST() {
  const session = await auth();
  if (!session.isSignedIn) return Response.json({ error: "unauthenticated" }, { status: 401 });
  try {
    session.requireRecentAuth({ maxAge: 300, level: "first_factor" });
  } catch (e) {
    if (e instanceof ReverificationRequiredError) return e.toResponse();
    throw e;
  }
  return Response.json({ ok: true, userId: session.userId });
}
