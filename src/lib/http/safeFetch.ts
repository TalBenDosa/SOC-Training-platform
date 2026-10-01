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
