import { AuthStatus } from "./auth-status";

// Static server component; only the auth-aware island ships JS.
export default function Home() {
  return (
    <main style={{ maxWidth: 640, margin: "80px auto", padding: "0 16px" }}>
      <h1>Example app</h1>
      <AuthStatus />
    </main>
  );
}
