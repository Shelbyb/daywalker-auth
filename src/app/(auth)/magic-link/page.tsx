import { MagicLink } from "@/app/components/magic-link";
import { parsePublishableKey, getInstance } from "@/lib/auth/instance";

export const metadata = { title: "Sign in", referrer: "no-referrer" };

export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { pk } = await searchParams;
  const id = parsePublishableKey(pk);
  const inst = id ? await getInstance(id) : null;
  if (!pk || !inst) return <p className="text-center text-sm text-stone-500">Missing or invalid publishable key.</p>;
  return (
    <>
      <div className="mb-6 h-1 w-10 rounded-full bg-gradient-to-r from-dawn to-ember" />
      <MagicLink pk={pk} appName={inst.name} />
    </>
  );
}
