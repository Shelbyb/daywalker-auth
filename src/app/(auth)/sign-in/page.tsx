import { HostedAuth } from "@/app/components/hosted-auth";
import { hostedInstance } from "@/lib/hosted";
import { BrandStyle } from "@/app/components/brand-style";
import { safeRedirect } from "@/lib/auth/redirect";
import { publicEnvironment } from "@/lib/auth/environment";

export const metadata = { title: "Sign in" };

export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { pk: pkParam, redirect_url, error, status } = await searchParams;
  const h = await hostedInstance(pkParam);
  const pk = h?.pk, inst = h?.inst;
  if (!pk || !inst) return <p className="text-center text-sm text-stone-500">Missing or invalid publishable key.</p>;
  const redirect = safeRedirect(redirect_url, inst.allowedOrigins) ?? safeRedirect(inst.settings.redirects?.afterSignIn ?? undefined, inst.allowedOrigins) ?? undefined;
  const q = (extra: Record<string, string>) => new URLSearchParams({ pk, ...(redirect ? { redirect_url: redirect } : {}), ...extra }).toString();
  return (
    <>
    <BrandStyle inst={inst} />
    <HostedAuth
      mode="sign-in"
      pk={pk}
      origin={h!.origin}
      redirect={redirect}
      returnTo={`${h!.origin}/sign-in?${q({ status: "signed_in" })}`}
      otherUrl={`/sign-up?${q({})}`}
      environment={await publicEnvironment(inst)}
      error={error}
      signedIn={status === "signed_in"}
    />
    </>
  );
}
