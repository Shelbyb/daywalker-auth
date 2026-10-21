import { requireUser } from "./guard";
import { Shell } from "./shell";

export const metadata = { title: { default: "Dashboard", template: "%s · Daywalker Auth" }, robots: { index: false } };

// Never cache: every request depends on the viewer's cookie.
export const dynamic = "force-dynamic";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  await requireUser();
  return <Shell>{children}</Shell>;
}
