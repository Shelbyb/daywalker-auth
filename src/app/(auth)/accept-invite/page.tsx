import { AcceptInvite } from "@/app/components/accept-invite";
import { parsePublishableKey, getInstance } from "@/lib/auth/instance";
import { safeRedirect } from "@/lib/auth/redirect";

export const metadata = { title: "Accept invitation", robots: { index: false } };

export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { pk, token, redirect_url } = await searchParams;
  const id = parsePublishableKey(pk);
  const inst = id ? await getInstance(id) : null;
  if (!pk || !inst || !token) return <p className="text-center text-sm text-stone-500">This invitation link is incomplete.</p>;
  return (
    <>
      <div className="mb-6 h-1 w-10 rounded-full bg-gradient-to-r from-dawn to-ember" />
      <AcceptInvite pk={pk} token={token} appName={inst.name} redirect={safeRedirect(redirect_url, inst.allowedOrigins) ?? undefined} />
    </>
  );
}
