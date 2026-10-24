import Link from "next/link";

export const PAGE_SIZES = [10, 25, 50, 100] as const;

/** Reads `?size=` from the URL; unknown values fall back to the default. */
export function pageSize(sp: Record<string, string | string[] | undefined>, def = 10): number {
  const n = Number(typeof sp.size === "string" ? sp.size : 0);
  return (PAGE_SIZES as readonly number[]).includes(n) ? n : def;
}

/** Reads a 1-based `?page=`. */
export function pageNum(sp: Record<string, string | string[] | undefined>): number {
  return Math.min(Math.max(parseInt(typeof sp.page === "string" ? sp.page : "1", 10) || 1, 1), 100_000);
}

const link = "font-medium underline decoration-dawn decoration-2 underline-offset-4";

/**
 * Previous/next links plus a page-size picker. Offset lists pass `page`;
 * cursor lists pass `cursor` (current) and `nextCursor`.
 */
export function Pager({ base, params = {}, size, defaultSize = 10, page, hasNext, cursor, nextCursor }: {
  base: string;
  params?: Record<string, string | undefined>;
  size: number;
  defaultSize?: number;
  page?: number;
  hasNext?: boolean;
  cursor?: string;
  nextCursor?: string | null;
}) {
  const href = (extra: Record<string, string | undefined>) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries({ ...params, ...extra })) if (v) p.set(k, v);
    return p.size ? `${base}?${p}` : base;
  };
  const sizeQ = (s: number) => (s === defaultSize ? undefined : String(s));
  const byCursor = page === undefined;
  return (
    <nav aria-label="Pagination" className="flex flex-wrap items-center justify-between gap-3 text-sm">
      <span className="flex items-center gap-3">
        {byCursor
          ? cursor ? <Link href={href({ size: sizeQ(size) })} className={link}>&larr; Newest</Link> : null
          : page! > 1 ? <Link href={href({ page: page! > 2 ? String(page! - 1) : undefined, size: sizeQ(size) })} className={link}>&larr; Previous</Link> : null}
        {!byCursor && <span className="text-stone-500">Page {page}</span>}
        {(byCursor ? nextCursor : hasNext) ? (
          <Link href={href(byCursor ? { before: nextCursor ?? undefined, size: sizeQ(size) } : { page: String(page! + 1), size: sizeQ(size) })} className={link}>
            {byCursor ? "Older" : "Next"} &rarr;
          </Link>
        ) : null}
      </span>
      <span className="flex items-center gap-2 text-stone-500">
        Per page
        {PAGE_SIZES.map((s) => (
          <Link key={s} href={href({ page: undefined, before: undefined, size: sizeQ(s) })} aria-current={s === size ? "true" : undefined} className={s === size ? "font-semibold text-ink underline underline-offset-4" : "hover:text-ink"}>
            {s}
          </Link>
        ))}
      </span>
    </nav>
  );
}
