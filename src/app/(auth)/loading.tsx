// Streams the card skeleton instantly while the instance lookup runs.
export default function Loading() {
  return (
    <div className="animate-pulse space-y-4" aria-busy="true">
      <div className="h-1 w-10 rounded-full bg-stone-200" />
      <div className="h-6 w-32 rounded bg-stone-200" />
      <div className="h-10 rounded-lg bg-stone-100" />
      <div className="h-10 rounded-lg bg-stone-100" />
      <div className="h-10 rounded-lg bg-stone-200" />
    </div>
  );
}
