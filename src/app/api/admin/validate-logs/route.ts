/**
 * GET /api/admin/validate-logs
 * ─────────────────────────────
 * Collects every TelemetryEvent in the platform (BENIGN_EVENTS +
 * all company-profile event pools) and runs the log validator over them.
 *
 * Returns a ValidationReport JSON with:
 *  - total / clean event counts
 *  - per-vendor and per-source breakdowns
 *  - full list of ValidationIssues (errors, warnings, infos)
 *
 * Usage:
 *   curl http://localhost:3000/api/admin/validate-logs | jq .summary
 */

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { validateEvents } from "@/lib/sim/logValidator";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS, COMPANY_ATTACKS } from "@/lib/sim/companyProfiles";
import { requireAdmin } from "@/lib/auth/apiGuard";

export async function GET(_req: NextRequest) {
  const gate = await requireAdmin();
  if ("error" in gate) return gate.error;

  // ── 1. Collect all events across every data source ──────────────────────
  // Start with NexaCorp's benign background events
  const allEvents: (typeof BENIGN_EVENTS)[0][] = [...BENIGN_EVENTS];

  // Add per-company benign event pools
  for (const events of Object.values(COMPANY_EVENTS)) {
    allEvents.push(...events);
  }

  // Add per-company attack chains (these are real event data too)
  for (const events of Object.values(COMPANY_ATTACKS)) {
    allEvents.push(...events);
  }

  // ── 2. Run validation ────────────────────────────────────────────────────
  const report = validateEvents(allEvents);

  // ── 3. Return JSON ───────────────────────────────────────────────────────
  return NextResponse.json(report, {
    headers: {
      // Prevent caching — results should always be fresh
      "Cache-Control": "no-store",
    },
  });
}
