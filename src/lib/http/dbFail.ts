import { NextResponse } from "next/server";

/**
 * The response for a failed database / storage / auth call in an API route
 * (QA phase 7, E-07). Routes returned the raw `error.message` — Postgres text like
 * `invalid input syntax for type uuid: "abc"` or a constraint name — to students
 * and staff alike, and logged nothing server-side. This logs the detail with the
 * route and returns a plain message; well-known Postgres codes map to the status
 * the client actually caused.
 */
export function dbFail(err: unknown, route: string, status = 500): NextResponse {
  const e = (err ?? {}) as { message?: unknown; code?: unknown };
  const code = typeof e.code === "string" ? e.code : "";
  console.error(`[${route}] ${code ? `${code} ` : ""}${typeof e.message === "string" ? e.message : String(err)}`);
  if (code === "22P02" || code === "PGRST116") return NextResponse.json({ error: "Not found." }, { status: 404 });
  if (code === "23505") return NextResponse.json({ error: "That already exists." }, { status: 409 });
  if (code === "23503") return NextResponse.json({ error: "That refers to something that no longer exists." }, { status: 409 });
  if (status === 400) return NextResponse.json({ error: "That request isn't valid." }, { status: 400 });
  if (status === 404) return NextResponse.json({ error: "Not found." }, { status: 404 });
  return NextResponse.json({ error: "Something went wrong on our side — please try again." }, { status: status >= 500 ? status : 500 });
}
