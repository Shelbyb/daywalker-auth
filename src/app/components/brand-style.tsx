import type { Instance } from "@/lib/db/schema";

const HEX = /^#[0-9a-fA-F]{6}$/;

/** Applies an instance's saved colors, logo and heading. Values are re-validated here, so only hex colors and https URLs reach the page. */
export function BrandStyle({ inst }: { inst: Pick<Instance, "settings"> }) {
  const b = inst.settings.branding;
  if (!b) return null;
  const rules: string[] = [];
  if (b.primaryColor && HEX.test(b.primaryColor)) rules.push(`.dw-button-primary{background:${b.primaryColor}!important;border-color:${b.primaryColor}!important}`);
  if (b.backgroundColor && HEX.test(b.backgroundColor)) rules.push(`body,main{background:${b.backgroundColor}!important}`);
  const logo = b.logoUrl?.startsWith("https://") ? b.logoUrl : null;
  return (
    <>
      {rules.length > 0 && <style>{rules.join("")}</style>}
      {/* eslint-disable-next-line @next/next/no-img-element */}
      {logo && <img src={logo} alt="" className="mb-4 max-h-12 w-auto" />}
    </>
  );
}
