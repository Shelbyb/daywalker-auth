import { CancelDeletion } from "@/app/components/cancel-deletion";
import { parsePublishableKey, getInstance } from "@/lib/auth/instance";

export const metadata = { title: "Keep account", referrer: "no-referrer" };

export default async function Page({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const { pk } = await searchParams;
  const id = parsePublishableKey(pk);
  const inst = id ? await getInstance(id) : null;
  if (!pk || !inst) return <p className="text-center text-sm text-stone-500">Missing or invalid publishable key.</p>;
  return (
    <>
      <div className="mb-6 h-1 w-10 rounded-full bg-gradient-to-r from-dawn to-ember" />
      <CancelDeletion pk={pk} appName={inst.name} />
    </>
  );
}
