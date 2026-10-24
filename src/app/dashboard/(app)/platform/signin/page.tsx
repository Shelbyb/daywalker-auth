import Link from "next/link";
import { notFound } from "next/navigation";
import { requirePlatformPage } from "../../guard";
import { Card, PageHeader } from "../../ui";
import { env } from "@/lib/env";
import { parsePublishableKey } from "@/lib/auth/instance";

export const metadata = { title: "Platform sign-in" };

/** Sign-in options for the platform itself (this dashboard). Separate from what customers offer their own users. */
export default async function PlatformSignInPage() {
  await requirePlatformPage("/dashboard/platform/signin", "admin");
  const id = parsePublishableKey(env().PLATFORM_PUBLISHABLE_KEY);
  if (!id) notFound();
  const base = `/dashboard/instances/${encodeURIComponent(id)}`;
  const link = "font-medium underline decoration-dawn decoration-2 underline-offset-4";
  return (
    <div className="space-y-6">
      <PageHeader title="Platform sign-in" description="How staff and developers sign in to this dashboard. These settings only affect the platform's own login, not the sign-in options your customers offer." />
      <Card>
        <h2 className="font-semibold">Two-factor authentication</h2>
        <p className="mt-1 text-sm text-stone-600">Require two-factor for everyone, and turn on SMS codes, under <Link href={`${base}/settings`} className={link}>Settings</Link> (policy and SMS) . Users add authenticator apps, security keys and passkeys at <Link href="/dashboard/settings" className={link}>Account settings</Link>.</p>
      </Card>
      <Card>
        <h2 className="font-semibold">Social sign-in</h2>
        <p className="mt-1 text-sm text-stone-600">Enable Google, GitHub, Microsoft and others for dashboard sign-in under <Link href={`${base}/social`} className={link}>Social sign-in</Link>. Use your own OAuth app credentials.</p>
      </Card>
    </div>
  );
}
