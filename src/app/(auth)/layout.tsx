import "@daywalker/auth/styles.css";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-dvh items-center justify-center bg-gradient-to-b from-stone-100 to-stone-200 px-4">
      <div className="w-full max-w-sm rounded-2xl border border-stone-200 bg-white p-8 shadow-xl shadow-stone-300/40">
        {children}
      </div>
    </main>
  );
}
