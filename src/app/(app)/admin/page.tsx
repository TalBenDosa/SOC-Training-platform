import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Cog, Users, BookOpen, Shield, Database, Activity } from "lucide-react";

export const metadata = { title: "Admin" };

export default function AdminPage() {
  return (
    <div>
      <Topbar title="Admin Panel" subtitle="Tenant, user, content, and platform health" />
      <div className="container mx-auto max-w-[1400px] px-6 py-6 space-y-6">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {[
            { l: "Active Users (24h)", v: "412", i: Users },
            { l: "Scenarios Run",      v: "1,284", i: Activity },
            { l: "Detections Live",    v: "138", i: Shield },
            { l: "Telemetry / day",    v: "3.2M", i: Database },
          ].map(s => (
            <Card key={s.l} padded={false} className="p-4">
              <p className="text-[10px] uppercase tracking-widest text-slate-500">{s.l}</p>
              <p className="mt-1 font-mono text-2xl font-bold text-white">{s.v}</p>
            </Card>
          ))}
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card>
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Users</h3>
              <Button size="sm" variant="primary">+ Invite</Button>
            </div>
            <ul className="mt-3 divide-y divide-border">
              {[
                ["alice@cryotech.io",  "admin",        "active"],
                ["ben@cryotech.io",    "instructor",   "active"],
                ["carol@cryotech.io",  "senior_analyst","active"],
                ["dan@cryotech.io",    "analyst",      "invited"],
                ["eve@cryotech.io",    "threat_hunter","active"],
                ["frank@cryotech.io",  "analyst",      "suspended"],
              ].map(([email, role, status]) => (
                <li key={email as string} className="flex items-center justify-between py-2 text-xs">
                  <span className="font-mono text-slate-200">{email}</span>
                  <div className="flex gap-2">
                    <Badge variant="outline">{role}</Badge>
                    <span className={
                      status === "active"    ? "rounded bg-neon-green/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-neon-green" :
                      status === "invited"   ? "rounded bg-cyber-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-cyber-300" :
                                               "rounded bg-severity-critical/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-severity-critical"}>
                      {status}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          </Card>

          <Card>
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Content</h3>
              <Button size="sm" variant="secondary"><BookOpen className="h-4 w-4" /> New Scenario</Button>
            </div>
            <ul className="mt-3 divide-y divide-border text-xs">
              {[
                ["Phishing → Cloud Exfiltration", "intermediate", "published"],
                ["Password Spray → BEC Mailbox Rule", "beginner", "published"],
                ["Ransomware: Foothold to Encryption", "advanced", "draft"],
                ["OAuth Consent Phishing", "advanced", "draft"],
              ].map(([t, d, s]) => (
                <li key={t as string} className="flex items-center justify-between py-2">
                  <span className="text-slate-200">{t}</span>
                  <div className="flex gap-2">
                    <Badge variant="outline">{d}</Badge>
                    <span className={
                      s === "published" ? "rounded bg-neon-green/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-neon-green" :
                                          "rounded bg-slate-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-slate-400"}>
                      {s}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          </Card>

          <Card className="lg:col-span-2">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Platform settings</h3>
              <Button size="sm" variant="secondary"><Cog className="h-4 w-4" /> Edit</Button>
            </div>
            <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
              <div className="rounded border border-border bg-bg p-3">
                <p className="text-[10px] uppercase tracking-widest text-slate-500">Tenant</p>
                <p className="mt-1 font-mono text-sm text-cyber-300">cryotech-prod</p>
              </div>
              <div className="rounded border border-border bg-bg p-3">
                <p className="text-[10px] uppercase tracking-widest text-slate-500">AI Model</p>
                <p className="mt-1 font-mono text-sm text-cyber-300">claude-opus-4-7</p>
              </div>
              <div className="rounded border border-border bg-bg p-3">
                <p className="text-[10px] uppercase tracking-widest text-slate-500">Region</p>
                <p className="mt-1 font-mono text-sm text-cyber-300">us-west-2</p>
              </div>
              <div className="rounded border border-border bg-bg p-3">
                <p className="text-[10px] uppercase tracking-widest text-slate-500">SSO</p>
                <p className="mt-1 font-mono text-sm text-neon-green">Enabled (Okta)</p>
              </div>
              <div className="rounded border border-border bg-bg p-3">
                <p className="text-[10px] uppercase tracking-widest text-slate-500">Audit Log</p>
                <p className="mt-1 font-mono text-sm text-neon-green">Streaming to S3</p>
              </div>
              <div className="rounded border border-border bg-bg p-3">
                <p className="text-[10px] uppercase tracking-widest text-slate-500">Retention</p>
                <p className="mt-1 font-mono text-sm text-cyber-300">365 days</p>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
