"use client";
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useTeamSentinel } from "@/lib/team/useTeamSentinel";
import { useTeamHeartbeat } from "@/lib/team/useTeamHeartbeat";
import { SentinelConsole } from "@/components/sentinel/SentinelConsole";
import { sentinelChannelName, sentinelWindowName, showSiemWindow, type SentinelTarget } from "@/lib/team/twoWindows";

const UUID = /^[0-9a-fA-F-]{36}$/;

/**
 * XDR, the investigation console of a Team Training session, opened from the team room in its own
 * tab (/sentinel redirects here with its query, for old links and open windows).
 * ?team=<session id> is required: there is no XDR workspace outside an exercise that chose it.
 * ?r= is display only (the database gate decides every action). ?incident= and ?host= open that item.
 */
export default function XdrPage() {
  const params = useSearchParams();
  const raw = params.get("team");
  const team = raw && UUID.test(raw) ? raw : null;
  const r = params.get("r");
  const role = r && /^[a-z0-9]{1,16}$/.test(r) ? r : null;
  const { workspace, states, actions, loading, error, ended, paused, looseBookmarks, refresh } = useTeamSentinel(team, role);
  // Working here counts as being on shift, as in the EDR console: the SIEM window may be closed.
  useTeamHeartbeat(ended ? null : team);
  const initial = useMemo(() => ({ incidentId: params.get("incident") ?? undefined, host: params.get("host") ?? undefined }), [params]);
  const [goTo, setGoTo] = useState<{ incidentId?: string; host?: string; nonce: number } | undefined>();

  // This tab is the session's XDR window, and the SIEM window can send the analyst to an incident.
  useEffect(() => {
    if (!team) return;
    window.name = sentinelWindowName(team);
    try {
      const ch = new BroadcastChannel(sentinelChannelName(team));
      ch.onmessage = (e: MessageEvent<SentinelTarget>) => setGoTo(g => ({ incidentId: e.data.incident, host: e.data.host, nonce: (g?.nonce ?? 0) + 1 }));
      return () => ch.close();
    } catch { return; }
  }, [team]);

  if (!team) return <Notice title="XDR opens from a team exercise" text="Open it from the team room of a session that investigates in XDR." />;
  if (loading) return <Notice title="Connecting to the workspace" text="Reading the session's logs." />;
  if (!workspace || !actions) return <Notice title="This workspace could not be opened" text={error ?? "Reload the page, or go back to the team room."} team={team} />;

  return <SentinelConsole workspace={workspace} states={states} actions={actions} onRefresh={refresh} ended={ended} backHref={`/team/${team}`} initial={initial} goTo={goTo} onBack={() => showSiemWindow(team, `/team/${team}`)} paused={paused} savedBookmarks={looseBookmarks} sessionKey={team} />;
}

function Notice({ title, text, team }: { title: string; text: string; team?: string }) {
  return (
    <div className="flex min-h-[60vh] items-center justify-center p-6">
      <div role="status" className="max-w-md rounded-xl border border-border bg-bg-panel p-6 text-center">
        <h1 className="text-lg font-bold text-white">{title}</h1>
        <p className="mt-2 text-sm text-slate-400">{text}</p>
        <Link href={team ? `/team/${team}` : "/team"} className="mt-4 inline-block rounded-lg bg-cyber-500 px-4 py-2 text-sm font-semibold text-[var(--on-accent)] hover:bg-cyber-400">Back to the team room</Link>
      </div>
    </div>
  );
}
