import { AuthForm } from "@/app/components/auth-form";
import { parsePublishableKey, getInstance } from "@/lib/auth/instance";
import { safeRedirect } from "@/lib/auth/redirect";
import { enabledProviders } from "@/lib/auth/oauth";
import { legalOf } from "@/lib/auth/legal";
import { emailCodeEnabled } from "@/lib/auth/email-sign-in";

export const metadata = { title: "Sign in" };

export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { pk, redirect_url, error, status } = await searchParams;
  const id = parsePublishableKey(pk);
  const inst = id ? await getInstance(id) : null;
  if (!pk || !inst) return <p className="text-center text-sm text-stone-500">Missing or invalid publishable key.</p>;
  return (
    <>
      <div className="mb-6 h-1 w-10 rounded-full bg-gradient-to-r from-dawn to-ember" />
      <h1 className="mb-1 text-xl font-semibold">Sign in</h1>
      <p className="mb-6 text-sm text-stone-500">to continue to {inst.name}</p>
      <AuthForm
        mode="sign-in"
        pk={pk}
        redirect={safeRedirect(redirect_url, inst.allowedOrigins) ?? undefined}
        providers={await enabledProviders(inst.id)}
        initialError={error}
        signedIn={status === "signed_in"}
        legal={legalOf(inst)}
        emailCode={emailCodeEnabled(inst)}
      />
    </>
  );
}
