import { env } from "@/lib/env";
import { requireUser } from "../guard";
import { AccountView } from "@/app/components/account/account-view";

export const metadata = { title: "Account settings" };

/** The developer's own account: profile, password, passkeys, two-factor and signed-in devices. */
export default async function SettingsPage() {
  await requireUser();
  const pk = env().PLATFORM_PUBLISHABLE_KEY ?? "";
  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="mb-6 text-2xl font-semibold">Account settings</h1>
      <AccountView pk={pk} back="/dashboard" />
    </div>
  );
}
