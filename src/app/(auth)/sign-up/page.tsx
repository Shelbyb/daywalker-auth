import { AuthForm } from "@/app/components/auth-form";
import { parsePublishableKey, getInstance } from "@/lib/auth/instance";
import { safeRedirect } from "@/lib/auth/redirect";

export const metadata = { title: "Create your account" };

export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { pk, redirect_url } = await searchParams;
  const id = parsePublishableKey(pk);
  const inst = id ? await getInstance(id) : null;
  if (!pk || !inst) return <p className="text-center text-sm text-stone-500">Missing or invalid publishable key.</p>;
  return (
    <>
      <div className="mb-6 h-1 w-10 rounded-full bg-gradient-to-r from-dawn to-ember" />
      <h1 className="mb-1 text-xl font-semibold">Create your account</h1>
      <p className="mb-6 text-sm text-stone-500">to continue to {inst.name}</p>
      <AuthForm mode="sign-up" pk={pk} redirect={safeRedirect(redirect_url, inst.allowedOrigins) ?? undefined} />
    </>
  );
}
