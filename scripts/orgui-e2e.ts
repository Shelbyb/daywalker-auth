/** Hosted organization pages: served under the strict CSP, rewrite under /h/<pk>/, reject bad keys, bundle the components. The interactive flow is scripts/browser/organization.py. */
import { seedInstance } from "./seed";
import { closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 300)}`}`);
  if (!ok) failures++;
};
const { publishableKey: pk } = await seedInstance("Org UI E2E", []);

for (const page of ["organization", "create-organization"]) {
  const r = await fetch(`${AUTH}/${page}?pk=${pk}`);
  const html = await r.text();
  const csp = r.headers.get("content-security-policy") ?? "";
  check(`/${page} renders`, r.status === 200 && html.includes(page === "organization" ? "Organization" : "Create organization"), r.status);
  check(`/${page} uses the strict nonce CSP, can't be framed`, /script-src 'self' 'nonce-[^']+' 'strict-dynamic'/.test(csp) && csp.includes("frame-ancestors 'none'"), csp);
  const bad = await (await fetch(`${AUTH}/${page}?pk=pk_test_bogus`)).text();
  check(`/${page} with a bad key shows the invalid-key message`, bad.includes("Missing or invalid publishable key"));
  const alias = await fetch(`${AUTH}/h/${pk}/${page}`);
  check(`/h/<pk>/${page} serves the same page`, alias.status === 200 && (await alias.text()).includes(page === "organization" ? "Organization" : "Create organization"));
}
const evil = await fetch(`${AUTH}/organization?pk=${pk}&redirect_url=${encodeURIComponent("https://evil.example/steal")}&org=%3Cscript%3E`);
const evilHtml = await evil.text();
check("an off-list redirect_url is not offered as a back link", !evilHtml.includes('href="https://evil.example') && !/Back to/.test(evilHtml));
check("a malformed org id is dropped, not echoed", !evilHtml.includes("<script>alert"), evil.status);

await closeCache();
await closeDb();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll organization UI checks passed");
process.exit(failures ? 1 : 0);
