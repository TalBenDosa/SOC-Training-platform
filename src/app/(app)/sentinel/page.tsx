import { redirect } from "next/navigation";
import { xdrHref, type SearchParams } from "@/lib/team/twoWindows";

/**
 * The console's old address. It is XDR now (owner, 2026-11-08), at /xdr: old links, bookmarks and
 * windows opened before the rename land there with the same query (team, u, r, incident, host).
 */
export default async function SentinelRedirect({ searchParams }: { searchParams: Promise<SearchParams> }) {
  redirect(xdrHref(await searchParams));
}
