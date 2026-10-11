/**
 * fetch that never throws: a network failure (offline, DNS, dropped connection)
 * resolves to `null` instead of rejecting. Client handlers that set a busy /
 * loading flag before awaiting fetch used to leave it stuck forever when the
 * request rejected (QA P5-07); with this they can show a retryable message.
 */
export const NETWORK_ERROR = "Couldn't reach the server — check your connection and try again.";

export async function safeFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response | null> {
  try {
    return await fetch(input, init);
  } catch {
    return null;
  }
}

/**
 * fetch whose network failure becomes an ordinary 503 Response carrying
 * {error: NETWORK_ERROR} (QA phase 7, E-10). Staff consoles did
 * `setBusy(true); const res = await fetch(…); setBusy(false)` with no catch, so a
 * dropped connection skipped every reset — Save / Enter / Approve stayed disabled
 * and loaders sat on "Loading…" until a reload. With this, the code's existing
 * `if (!res.ok) setError(body.error)` path handles it.
 */
export async function fetchOrError(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  try {
    return await fetch(input, init);
  } catch {
    return new Response(JSON.stringify({ error: NETWORK_ERROR }), { status: 503, headers: { "Content-Type": "application/json" } });
  }
}
