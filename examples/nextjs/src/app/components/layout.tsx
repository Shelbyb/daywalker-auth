import "@daywalker/auth/styles.css";
import { Header } from "./header";

/** Demo of the drop-in components. Everything here is the SDK; no custom auth UI. */
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <Header />
      <main style={{ display: "grid", placeItems: "center", padding: "48px 16px" }}>{children}</main>
    </>
  );
}
