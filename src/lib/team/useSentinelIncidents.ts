"use client";
import { useEffect, useMemo, useState } from "react";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { Stack } from "@/lib/logs/native/stack";
import type { Ev, SessionMeta } from "@/lib/team/types";
import { hostKey } from "@/lib/team/format";
import { escalatedCases } from "@/lib/team/investigationConsole";

export interface TeamRoomIncident { id: string; number: number; title: string; hosts: string[] }

/**
 * The Sentinel incidents the team room shows on its button and notices, in place of EDR alerts.
 * Built from the same released events with the same builder as the console's tab, so numbers and
 * titles match. The builder loads only for a Sentinel session: an EDR session never pays for it.
 */
export function useSentinelIncidents(enabled: boolean, feed: Ev[], events: Ev[], session: SessionMeta | null): TeamRoomIncident[] {
  const [mod, setMod] = useState<typeof import("@/lib/sentinel/workspace") | null>(null);
  useEffect(() => {
    if (!enabled || mod) return;
    let alive = true;
    import("@/lib/sentinel/workspace").then(m => { if (alive) setMod(m); }).catch(() => { /* the button still opens Sentinel */ });
    return () => { alive = false; };
  }, [enabled, mod]);

  const stackKey = JSON.stringify(session?.stack ?? {});
  const escalationKey = JSON.stringify(enabled ? escalatedCases(events) : []);
  const companyId = session?.company_id;
  const domain = session?.tenant?.domain, netbios = session?.tenant?.netbios, org = session?.tenant?.name;
  return useMemo(() => {
    if (!enabled || !mod || !companyId) return [];
    const evs = feed.map(e => { const t = e.payload as unknown as TelemetryEvent; return e.occurred_at ? withRebasedTime(t, e.occurred_at) : t; });
    const ws = mod.buildWorkspace(evs, { companyId, stack: JSON.parse(stackKey) as Stack, identity: domain && netbios ? { domain, netbios } : undefined, orgName: org, escalated: JSON.parse(escalationKey) });
    return ws.incidents.map(i => ({
      id: i.id, number: i.number, title: i.title,
      hosts: i.entityIds.map(x => ws.entities[x]).filter(x => x?.kind === "host").map(x => hostKey(x.name)),
    }));
  }, [enabled, mod, feed, companyId, stackKey, domain, netbios, org, escalationKey]);
}
