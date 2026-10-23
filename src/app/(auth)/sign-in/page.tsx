import { HostedAuth } from "@/app/components/hosted-auth";
import { parsePublishableKey, getInstance } from "@/lib/auth/instance";
import { safeRedirect } from "@/lib/auth/redirect";
import { publicEnvironment } from "@/lib/auth/environment";
import { env } from "@/lib/env";

export const metadata = { title: "Sign in" };

export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { pk, redirect_url, error, status } = await searchParams;
  const id = parsePublishableKey(pk);
  const inst = id ? await getInstance(id) : null;
  if (!pk || !inst) return <p className="text-center text-sm text-stone-500">Missing or invalid publishable key.</p>;
  const redirect = safeRedirect(redirect_url, inst.allowedOrigins) ?? undefined;
  const q = (extra: Record<string, string>) => new URLSearchParams({ pk, ...(redirect ? { redirect_url: redirect } : {}), ...extra }).toString();
  return (
    <HostedAuth
      mode="sign-in"
      pk={pk}
      origin={env().APP_URL}
      redirect={redirect}
      returnTo={`${env().APP_URL}/sign-in?${q({ status: "signed_in" })}`}
      otherUrl={`/sign-up?${q({})}`}
      environment={await publicEnvironment(inst)}
      error={error}
      signedIn={status === "signed_in"}
    />
  );
}
