import { Suspense } from "react";
import Link from "next/link";
import { dashboardProfile, requireDashboardUser } from "@/lib/dashboard";
import { env } from "@/lib/env";
import { platformRole } from "@/lib/platform-staff";
import { SignOutButton } from "./sign-out";
import { HelpProvider } from "./help";

async function Email() {
  const { userId } = await requireDashboardUser();
  const { email } = await dashboardProfile(userId);
  return <span className="hidden max-w-[16rem] truncate text-sm text-stone-600 sm:inline">{email ?? "Signed in"}</span>;
}

/** Only platform staff see the link (the console itself re-checks the role). */
async function PlatformLink() {
  const { userId } = await requireDashboardUser();
  if (!(await platformRole(userId))) return null;
  return (
    <Link href="/dashboard/platform" className="text-sm font-medium text-stone-700 underline decoration-ember decoration-2 underline-offset-4 hover:text-ink">
      Platform
    </Link>
  );
}

/** Chrome around every dashboard page. The auth guard lives in layout.tsx and in each page. */
export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-dvh">
      <header className="border-b border-stone-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center gap-4 px-4 py-3">
          <Link href="/dashboard" className="rounded text-base font-semibold tracking-tight focus-visible:outline-2 focus-visible:outline-dawn">
            Daywalker Auth
          </Link>
          <div className="ml-auto flex items-center gap-4">
            <Suspense fallback={<span className="hidden h-4 w-32 animate-pulse rounded bg-stone-100 sm:inline-block" />}>
              <Email />
            </Suspense>
            <Suspense fallback={null}>
              <PlatformLink />
            </Suspense>
            <Link href="/dashboard/settings" className="text-sm font-medium text-stone-700 underline decoration-dawn decoration-2 underline-offset-4 hover:text-ink">
              Settings
            </Link>
            <Link href="/docs" className="text-sm font-medium text-stone-700 underline decoration-dawn decoration-2 underline-offset-4 hover:text-ink">
              Docs
            </Link>
            <SignOutButton publishableKey={env().PLATFORM_PUBLISHABLE_KEY ?? ""} />
          </div>
        </div>
      </header>
      <HelpProvider><main className="mx-auto max-w-6xl px-4 py-8">{children}</main></HelpProvider>
    </div>
  );
}
