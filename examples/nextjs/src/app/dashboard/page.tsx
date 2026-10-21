import { Suspense } from "react";
import Image from "next/image";
import { auth, backend } from "@daywalker/auth/nextjs";
import { CallApi } from "./call-api";

// The shell (heading + session line) streams immediately; the profile, which needs a
// backend API round-trip, streams in when ready behind a Suspense boundary.
export default async function Dashboard() {
  const session = await auth(); // local JWT verification, no network after first JWKS fetch
  if (!session.isSignedIn) return null; // proxy.ts already redirected signed-out users
  return (
    <main style={{ maxWidth: 640, margin: "80px auto", padding: "0 16px" }}>
      <h1>Dashboard</h1>
      <Suspense fallback={<p aria-busy="true">Loading profile…</p>}>
        <Profile userId={session.userId} />
      </Suspense>
      <p style={{ color: "#78716c", fontSize: 13 }}>Session {session.sessionId}</p>
      <CallApi />
    </main>
  );
}

async function Profile({ userId }: { userId: string }) {
  const user = await backend().users.get(userId);
  return (
    <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
      {user.imageUrl && (
        // next/image: resized, lazy-loaded, modern formats. Allow the host in next.config images.remotePatterns.
        <Image src={user.imageUrl} alt="" width={48} height={48} style={{ borderRadius: 999 }} />
      )}
      <p>
        Signed in as <strong>{user.emailAddresses[0]?.email}</strong>
      </p>
    </div>
  );
}
