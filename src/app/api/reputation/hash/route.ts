import { NextResponse } from "next/server";
import { SCENARIOS } from "@/lib/sim/scenarios";

export const runtime = "nodejs";

// Build a set of known malicious hashes from all scenarios (deterministic)
function buildMaliciousHashSet(): Set<string> {
  const s = new Set<string>();
  for (const entry of SCENARIOS) {
    const bundle = entry.build();
    for (const ioc of bundle.iocs) {
      if ((ioc.type === "sha256" || ioc.type === "md5") && ioc.reputation === "malicious") {
        s.add(ioc.value.toLowerCase());
      }
    }
  }
  return s;
}

let _hashSet: Set<string> | null = null;
function getMaliciousHashes() {
  if (!_hashSet) _hashSet = buildMaliciousHashSet();
  return _hashSet;
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const sha256 = (url.searchParams.get("sha256") ?? "").toLowerCase().trim();

  if (!sha256 || sha256.length < 32) {
    return NextResponse.json({ error: "Invalid hash" }, { status: 400 });
  }

  const malicious = getMaliciousHashes().has(sha256);
  const detections = malicious ? 43 + (sha256.charCodeAt(0) % 28) : 0;

  return NextResponse.json({
    sha256,
    malicious,
    detections,
    total_engines: 72,
    engine: "mock-VT",
    verdict: malicious ? "malicious" : "clean",
    first_seen: malicious ? "2026-02-14" : null,
  });
}
