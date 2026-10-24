import Link from "next/link";

export const metadata = { title: "Terms of Service" };

const sections: [string, string][] = [
  ["1. Acceptance", "By creating an account or using Daywalker Auth (the \"Service\"), you agree to these Terms. If you do not agree, do not use the Service."],
  ["2. The Service", "Daywalker Auth provides hosted authentication, user management and related developer tools. We may change or discontinue features with reasonable notice."],
  ["3. Your account", "You are responsible for your credentials, for activity under your account, and for keeping your contact details accurate. Tell us promptly about any unauthorized use."],
  ["4. Acceptable use", "You will not misuse the Service, attempt to breach its security, interfere with other customers, send spam, or use it for unlawful activity. We may suspend accounts that do."],
  ["5. Your data", "You keep ownership of the data you and your end users put into the Service. You are responsible for having the right to process it and for your own privacy notices to your end users. We process it only to provide the Service."],
  ["6. Plans and billing", "Paid plans are billed through Stripe and renew until cancelled. Fees are non-refundable except where required by law. We may change prices with advance notice."],
  ["7. Availability", "We aim for high availability but provide the Service \"as is\", without warranties of any kind, to the extent permitted by law."],
  ["8. Liability", "To the extent permitted by law, we are not liable for indirect or consequential damages, and our total liability is limited to the fees you paid in the 12 months before the claim."],
  ["9. Termination", "You may stop using the Service and delete your account at any time. We may suspend or terminate access for breach of these Terms."],
  ["10. Changes", "We may update these Terms. Continued use after changes take effect means you accept them."],
  ["11. Contact", "Questions about these Terms can be sent to the contact address shown on daywalker.dev."],
];

export default function TermsPage() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-14">
      <Link href="/" className="text-sm text-stone-500 hover:text-ink">← Daywalker Auth</Link>
      <h1 className="mt-6 text-3xl font-semibold text-ink">Terms of Service</h1>
      <p className="mt-2 text-sm text-stone-500">Last updated: October 23, 2026</p>
      <div className="mt-8 space-y-6 text-stone-700">
        {sections.map(([h, t]) => (
          <section key={h}>
            <h2 className="text-lg font-medium text-ink">{h}</h2>
            <p className="mt-1 leading-relaxed">{t}</p>
          </section>
        ))}
      </div>
    </main>
  );
}
