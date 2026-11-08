"use client";
import { useEffect, useMemo, useState } from "react";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import type { TelemetryEvent } from "@/lib/sim/types";
import { withoutDetectionFeed, type Stack } from "@/lib/logs/native/stack";
import type { Ev, SessionMeta } from "@/lib/team/types";
import { hostKey } from "@/lib/team/format";
import { escalatedCases } from "@/lib/team/investigationConsole";

export interface TeamRoomIncident {
  id: string; number: number; title: string; hosts: string[];
  /** Feed events behind it: a case (one escalated log) opens the incident that holds its log. */
  eventIds: string[];
}

/**
 * The Sentinel incidents the team room shows on its button and notices, in place of EDR alerts.
 * Built from the same released events with the same builder as the console's tab, so numbers and
 * titles match. The builder loads only for a Sentinel session: an EDR session never pays for it.
 */
/**
 * Which incident an "Investigate in Sentinel" opens: the one holding the case's log, else the one on
 * its host; with neither, none (the console opens on the incident list, never on whichever incident
 * came last: 2026-11-08 review).
 */
export function incidentForCase(incidents: TeamRoomIncident[], target: { eventId?: string; host?: string }): string | undefined {
  if (target.eventId) { const byLog = incidents.find(i => i.eventIds.includes(target.eventId!)); if (byLog) return byLog.id; }
  if (target.host) return incidents.find(i => i.hosts.includes(hostKey(target.host!)))?.id;
  return undefined;
}

export function useSentinelIncidents(enabled: boolean, feed: Ev[], events: Ev[], session: SessionMeta | null): TeamRoomIncident[] {
  const [mod, setMod] = useState<typeof import("@/lib/sentinel/workspace") | null>(null);
  useEffect(() => {
    if (!enabled || mod) return;
    let alive = true;
    import("@/lib/sentinel/workspace").then(m => { if (alive) setMod(m); }).catch(() => { /* the button still opens Sentinel */ });
    return () => { alive = false; };
  }, [enabled, mod]);

  // The workspace reads each log's own record (the Defender row, not its Graph alert).
  const stackKey = JSON.stringify(withoutDetectionFeed((session?.stack ?? {}) as Stack));
  const escalationKey = useMemo(() => JSON.stringify(enabled ? escalatedCases(events) : []), [enabled, events]);
  const companyId = session?.company_id;
  const domain = session?.tenant?.domain, netbios = session?.tenant?.netbios, org = session?.tenant?.name;
  return useMemo(() => {
    if (!enabled || !mod || !companyId) return [];
    const evs = feed.map(e => { const t = e.payload as unknown as TelemetryEvent; return e.occurred_at ? withRebasedTime(t, e.occurred_at) : t; });
    const ws = mod.buildWorkspace(evs, { companyId, stack: JSON.parse(stackKey) as Stack, identity: domain && netbios ? { domain, netbios } : undefined, orgName: org, escalated: JSON.parse(escalationKey), baseline: false });
    return ws.incidents.map(i => ({
      id: i.id, number: i.number, title: i.title,
      hosts: i.entityIds.map(x => ws.entities[x]).filter(x => x?.kind === "host").map(x => hostKey(x.name)),
      eventIds: [...new Set(i.alertIds.flatMap(a => ws.alertEventIds[a] ?? []))],
    }));
  }, [enabled, mod, feed, companyId, stackKey, domain, netbios, org, escalationKey]);
}
