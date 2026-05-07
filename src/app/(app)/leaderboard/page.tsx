import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { rankFromXp } from "@/lib/utils";
import { Crown, Flame, Trophy } from "lucide-react";

export const metadata = { title: "Leaderboard" };

const HANDLES = [
  "ghost.byte","null.terminator","cipher.kai","sentinel-7","raven.kim","quark.osinto","bytefoxx","red.echo","aurora.sec",
  "midnight.zero","void.relay","silica","triage.tor","kernel.ko","apex.hunt","forge.det","argon.0","p4ck3t",
  "neon.beacon","glitch.ops","sandbox.izzy","rootline","trace.mira","syslog.jay",
];

function generateLeaderboard() {
  return HANDLES.map((h, i) => {
    const xp = Math.round(82_000 * Math.pow(0.92, i)) + (HANDLES.length - i) * 50;
    const badges = Math.max(0, 24 - i + (i % 3));
    const completed = Math.max(0, 64 - i * 2);
    return { handle: h, xp, badges, completed };
  });
}

export default function LeaderboardPage() {
  const rows = generateLeaderboard();
  return (
    <div>
      <Topbar title="Global Leaderboard" subtitle="Across all SOCs in the simulator network" />
      <div className="container mx-auto max-w-[1400px] px-6 py-6 grid grid-cols-1 gap-4 lg:grid-cols-[2fr_1fr]">
        <Card padded={false}>
          <div className="grid grid-cols-[60px_1fr_120px_100px_120px_120px] items-center gap-4 border-b border-border px-5 py-3 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
            <div>Rank</div><div>Analyst</div><div>Rank Title</div><div>Level</div><div>XP</div><div>Badges</div>
          </div>
          {rows.map((r, i) => (
            <div key={r.handle}
              className={`grid grid-cols-[60px_1fr_120px_100px_120px_120px] items-center gap-4 border-b border-border/60 px-5 py-3 ${
                i === 0 ? "bg-gradient-to-r from-severity-medium/10 to-transparent" :
                i === 1 ? "bg-gradient-to-r from-cyber-500/5 to-transparent" :
                i === 2 ? "bg-gradient-to-r from-neon-purple/5 to-transparent" : ""
              }`}>
              <div className="flex items-center gap-2">
                {i === 0 ? <Crown className="h-4 w-4 text-severity-medium" /> :
                 i === 1 ? <Trophy className="h-4 w-4 text-slate-400" /> :
                 i === 2 ? <Trophy className="h-4 w-4 text-cyber-400" /> :
                 <span className="font-mono text-xs text-slate-500">#{i + 1}</span>}
              </div>
              <div className="flex items-center gap-3">
                <span className="flex h-8 w-8 items-center justify-center rounded-full border border-cyber-500/40 bg-cyber-500/10 font-mono text-xs font-bold text-cyber-300">
                  {r.handle.slice(0, 2).toUpperCase()}
                </span>
                <div>
                  <p className="font-mono text-sm text-white">@{r.handle}</p>
                  <p className="text-[10px] text-slate-500">{r.completed} scenarios completed</p>
                </div>
              </div>
              <Badge variant="outline">{rankFromXp(r.xp)}</Badge>
              <div className="font-mono text-sm text-cyber-300">L{Math.min(99, Math.floor(r.xp / 1000) + 1)}</div>
              <div className="flex items-center gap-2">
                <div className="h-1.5 w-20 overflow-hidden rounded bg-bg">
                  <div className="h-full bg-gradient-to-r from-cyber-500 to-neon-purple" style={{ width: `${Math.min(100, r.xp / 1000)}%` }} />
                </div>
                <span className="font-mono text-[11px] text-slate-300">{r.xp.toLocaleString()}</span>
              </div>
              <div className="flex items-center gap-1 text-xs text-slate-300">
                <Flame className="h-3.5 w-3.5 text-severity-medium" />
                {r.badges}
              </div>
            </div>
          ))}
        </Card>

        <div className="space-y-4">
          <Card>
            <h3 className="text-sm font-semibold text-white">Your stats</h3>
            <div className="mt-3 grid grid-cols-2 gap-2 text-center">
              {[
                ["XP", "8,420"],
                ["Level", "9"],
                ["Streak", "12 days"],
                ["Badges", "11"],
              ].map(([k, v]) => (
                <div key={k as string} className="rounded border border-border bg-bg p-2">
                  <p className="text-[10px] uppercase tracking-widest text-slate-500">{k}</p>
                  <p className="mt-1 font-mono text-lg text-cyber-300">{v}</p>
                </div>
              ))}
            </div>
          </Card>
          <Card>
            <h3 className="text-sm font-semibold text-white">Recent badges</h3>
            <ul className="mt-3 space-y-2 text-xs">
              {[
                ["First Triage", "bronze"],
                ["KQL Apprentice", "bronze"],
                ["MITRE Cartographer", "silver"],
                ["LSASS Hunter", "gold"],
                ["DNS Tunnel Spotter", "silver"],
              ].map(([n, t]) => (
                <li key={n as string} className="flex items-center justify-between rounded border border-border bg-bg px-2 py-1.5">
                  <span className="text-slate-200">{n}</span>
                  <span className={
                    t === "gold" ? "rounded bg-severity-medium/15 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-severity-medium" :
                    t === "silver" ? "rounded bg-slate-500/15 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-slate-300" :
                                     "rounded bg-cyber-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-cyber-300"}>
                    {t}
                  </span>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}
