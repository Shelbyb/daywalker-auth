import { SecondFactorRedirect } from "@/app/components/second-factor-redirect";
import { parsePublishableKey, getInstance } from "@/lib/auth/instance";
import { safeRedirect } from "@/lib/auth/redirect";

export const metadata = { title: "Two-step verification" };

/** Landing page after social sign-in for accounts with 2FA turned on. */
export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { pk, redirect_url } = await searchParams;
  const id = parsePublishableKey(pk);
  const inst = id ? await getInstance(id) : null;
  if (!pk || !inst) return <p className="text-center text-sm text-stone-500">Missing or invalid publishable key.</p>;
  return (
    <>
      <div className="mb-6 h-1 w-10 rounded-full bg-gradient-to-r from-dawn to-ember" />
      <SecondFactorRedirect pk={pk} redirect={safeRedirect(redirect_url, inst.allowedOrigins) ?? undefined} />
    </>
  );
}
