import Link from "next/link";
import { hostedInstance } from "@/lib/hosted";
import { BrandStyle } from "@/app/components/brand-style";
import { safeRedirect } from "@/lib/auth/redirect";
import { HostedOrg } from "@/app/components/hosted-org";
import "@daywalker/auth/styles.css";

export const metadata = { title: "Organization" };

/** Hosted page: /organization?pk=…&redirect_url=<back link>&org=<organization id> */
export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { pk: pkParam, redirect_url, org } = await searchParams;
  const h = await hostedInstance(pkParam);
  const pk = h?.pk, inst = h?.inst;
  if (!pk || !inst) return <main className="p-10 text-center text-sm text-stone-500">Missing or invalid publishable key.</main>;
  const back = safeRedirect(redirect_url, inst.allowedOrigins);
  const q = (path: string) => `${path}?pk=${encodeURIComponent(pk)}${back ? `&redirect_url=${encodeURIComponent(back)}` : ""}`;
  return (
    <main className="min-h-dvh bg-stone-100 px-4 py-10">
      <div className="mx-auto flex max-w-2xl flex-col items-center">
        <BrandStyle inst={inst} />
        <div className="mb-6 flex w-full items-center justify-between">
          <h1 className="text-2xl font-semibold">Organization</h1>
          {back && <Link href={back} className="text-sm font-medium text-stone-600 hover:text-ink">← Back to {inst.name}</Link>}
        </div>
        <HostedOrg kind="profile" pk={pk} origin={h.origin} organizationId={org && /^org_[0-9a-z]{22}$/.test(org) ? org : undefined} back={back ?? undefined} profileUrl={q("/organization")} createUrl={q("/create-organization")} />
      </div>
    </main>
  );
}
