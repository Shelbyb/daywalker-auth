/** Plain class strings, safe to import from server and client components alike. */
export const inputCls =
  "w-full rounded-lg border border-stone-300 bg-white px-3 py-2 text-sm outline-none focus:border-dawn focus:ring-2 focus:ring-dawn/30 aria-[invalid=true]:border-ember disabled:opacity-60";

const btnBase =
  "inline-flex items-center justify-center rounded-lg px-3.5 py-2 text-sm font-medium transition focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-dawn disabled:opacity-60";
export const btnCls = {
  primary: `${btnBase} bg-ink text-white hover:bg-dusk`,
  ghost: `${btnBase} border border-stone-300 bg-white text-stone-700 hover:bg-stone-100`,
  danger: `${btnBase} bg-ember text-white hover:bg-ember/90`,
};
export type Tone = keyof typeof btnCls;
