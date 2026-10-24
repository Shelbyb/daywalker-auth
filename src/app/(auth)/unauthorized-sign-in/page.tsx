import { hostedInstance } from "@/lib/hosted";
import { BrandStyle } from "@/app/components/brand-style";
import { safeRedirect } from "@/lib/auth/redirect";
import { unauthorizedMessage } from "@/lib/auth/unauthorized";

export const metadata = { title: "Unauthorized sign in" };

export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { pk: pkParam, redirect_url, reason } = await searchParams;
  const h = await hostedInstance(pkParam);
  const pk = h?.pk, inst = h?.inst;
  if (!pk || !inst) return <p className="text-center text-sm text-stone-500">Missing or invalid publishable key.</p>;
  // Only a code from the URL is used, mapped to a fixed message; unknown codes get the generic one.
  const msg = unauthorizedMessage(reason);
  const redirect = safeRedirect(redirect_url, inst.allowedOrigins) ?? undefined;
  const home = safeRedirect(inst.settings.redirects?.afterLogoClick ?? undefined, inst.allowedOrigins);
  const signIn = `/sign-in?${new URLSearchParams({ pk, ...(redirect ? { redirect_url: redirect } : {}) })}`;
  return (
    <>
      <BrandStyle inst={inst} />
      <div className="mb-6 h-1 w-10 rounded-full bg-gradient-to-r from-dawn to-ember" />
      <h1 className="mb-1 text-xl font-semibold">{msg.title}</h1>
      <p className="mb-6 text-sm text-stone-500">{inst.name}</p>
      <p role="alert" className="mb-6 text-sm">{msg.body}</p>
      <div className="flex flex-col gap-2 text-sm">
        <a href={signIn} className="font-medium underline">Back to sign in</a>
        {home && <a href={home} className="text-stone-500 underline">Go to {inst.name}</a>}
      </div>
    </>
  );
}
