import Link from "next/link";
import { hostedInstance } from "@/lib/hosted";
import { BrandStyle } from "@/app/components/brand-style";
import { safeRedirect } from "@/lib/auth/redirect";
import { AccountView } from "@/app/components/account/account-view";

export const metadata = { title: "Your account" };

/** Hosted account settings: /account?pk=…&redirect_url=<back link> */
export default async function AccountPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { pk: pkParam, redirect_url } = await searchParams;
  const h = await hostedInstance(pkParam);
  const pk = h?.pk, inst = h?.inst;
  if (!pk || !inst)
    return <main className="p-10 text-center text-sm text-stone-500">Missing or invalid publishable key.</main>;
  const back = safeRedirect(redirect_url, inst.allowedOrigins);
  return (
    <main className="min-h-dvh bg-stone-100 px-4 py-10">
      <div className="mx-auto max-w-2xl">
        <BrandStyle inst={inst} />
        <div className="mb-8 flex items-center justify-between">
          <div>
            <div className="mb-3 h-1 w-10 rounded-full bg-gradient-to-r from-dawn to-ember" />
            <h1 className="text-2xl font-semibold">Your account</h1>
            <p className="text-sm text-stone-500">{inst.name}</p>
          </div>
          {back && (
            <Link href={back} className="text-sm font-medium text-stone-600 hover:text-ink">← Back to {inst.name}</Link>
          )}
        </div>
        <AccountView pk={pk} back={back ?? undefined} />
      </div>
    </main>
  );
}
