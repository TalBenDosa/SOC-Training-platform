import Link from "next/link";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/Button";
import {
  Activity, BookOpen, ClipboardCheck, ClipboardList, DoorOpen,
  LayoutDashboard, Network, Target, TrendingUp,
} from "lucide-react";

export default function Landing() {
  return (
    <div className="relative min-h-screen overflow-hidden">
      {/* Background grid + glow */}
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[800px] bg-cyber-grid" />
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[800px] bg-cyber-glow" />

      {/* Top nav */}
      <header className="container mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
        <Logo />
        <nav className="hidden items-center gap-6 text-sm text-slate-300 md:flex">
          <a href="#features" className="hover:text-cyber-300">Platform</a>
          <a href="#tracks" className="hover:text-cyber-300">Curriculum</a>
          <Link href="/scenarios" className="hover:text-cyber-300">Scenarios</Link>
          <Link href="/rooms" className="hover:text-cyber-300">Learning Rooms</Link>
        </nav>
        <div className="flex items-center gap-3">
          {/* An account is now REQUIRED — every route below this page is gated
              in middleware, so the primary CTA points at /signup rather than
              deep-linking into the app and bouncing the visitor to /login. */}
          <Link href="/login" className="hidden text-sm text-slate-300 hover:text-cyber-300 sm:block">
            Sign in
          </Link>
          <Link href="/signup">
            <Button variant="primary">Create account</Button>
          </Link>
        </div>
      </header>

      {/* Hero */}
      <section className="container mx-auto max-w-7xl px-6 py-16 md:py-24">
        <div className="mx-auto max-w-3xl text-center">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyber-500/30 bg-cyber-500/5 px-3 py-1 text-xs">
            <span className="relative flex h-1.5 w-1.5"><span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon-green opacity-75" /><span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-neon-green" /></span>
            <span className="font-semibold uppercase tracking-widest text-cyber-200">Live SOC simulation engine</span>
          </div>
          <h1 className="mt-6 font-mono text-5xl font-extrabold tracking-tight text-white md:text-6xl">
            <span className="text-glow">HACK</span>{" "}
            <span className="text-cyber-400 text-glow">THE</span>{" "}
            <span className="text-glow">SOC</span>
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-balance text-base text-slate-300 md:text-lg">
            Train as a SOC analyst on a feed that breathes: real EDR process trees, vendor-accurate
            SIEM logs, and MITRE ATT&CK mappings, mostly normal activity with a real attack hidden
            inside. No hints — you write the incident report, and an AI grader checks it against
            the ground truth.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup"><Button size="lg" variant="primary">Start Learning — it&apos;s free</Button></Link>
            <Link href="/login"><Button size="lg" variant="outline">I already have an account</Button></Link>
          </div>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-xs text-slate-500">
            <span>Inspired by CrowdStrike Falcon · Microsoft Sentinel · Splunk · Elastic Security · IBM QRadar · Wazuh</span>
          </div>
        </div>

        {/* Hero panel: fake SOC dashboard preview */}
        <div className="mx-auto mt-14 max-w-6xl rounded-xl border border-border bg-bg-elevated/60 p-2 shadow-glow backdrop-blur">
          <div className="rounded-lg border border-border bg-bg p-4 md:p-6">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-3">
                <span className="h-2.5 w-2.5 rounded-full bg-severity-critical" />
                <span className="h-2.5 w-2.5 rounded-full bg-severity-medium" />
                <span className="h-2.5 w-2.5 rounded-full bg-neon-green" />
                <span className="ml-3 font-mono text-xs text-slate-500">soc.cryotech.io / live</span>
              </div>
              <span className="font-mono text-[10px] uppercase tracking-widest text-slate-500">tenant: demo</span>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
              {[
                { l: "Open Critical",  v: "07", a: "text-severity-critical" },
                { l: "Triaging",       v: "23", a: "text-neon-amber" },
                { l: "Mean Time to Triage", v: "4m 12s", a: "text-cyber-300" },
                { l: "Alerts / 24h",   v: "1,284", a: "text-neon-green" },
              ].map(s => (
                <div key={s.l} className="rounded-md border border-border bg-bg-elevated p-3">
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">{s.l}</p>
                  <p className={`mt-1 font-mono text-2xl font-bold ${s.a}`}>{s.v}</p>
                </div>
              ))}
            </div>
            <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-3">
              <div className="md:col-span-2 rounded-md border border-border bg-bg-elevated p-3">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-slate-500">Live alert feed</p>
                <ul className="space-y-1.5 font-mono text-xs">
                  {[
                    ["09:47:12","critical","CRWD-9F3A7C12","Encoded PowerShell from WINWORD.EXE","WS-FIN-3041"],
                    ["09:47:18","high","PAN-A8B12345","Outbound TLS to telemetry-api-3a8f1.xyz","WS-FIN-3041"],
                    ["09:47:30","high","SYSMON-0001","HKCU\\Run key WindowsUpdater added","WS-FIN-3041"],
                    ["09:48:02","critical","CRWD-9F3A7C5E","LSASS MiniDump via comsvcs.dll","WS-FIN-3041"],
                    ["09:51:44","high","OKTA-77BB12","Anomalous SSO from RU","a.park@cryotech.io"],
                    ["09:54:18","high","AWS-CT2278","S3 GetObject 184MB customer-exports","a.park@cryotech.io"],
                  ].map(([t, sev, id, msg, host]) => (
                    <li key={id} className="grid grid-cols-[60px_70px_120px_1fr_140px] gap-2 border-b border-border/50 py-1.5 text-slate-300 last:border-0">
                      <span className="text-slate-500">{t}</span>
                      <span className={
                        sev === "critical" ? "text-severity-critical" :
                        sev === "high" ? "text-severity-high" : "text-severity-medium"}>
                        {sev.toUpperCase()}
                      </span>
                      <span className="text-cyber-300">{id}</span>
                      <span className="truncate text-slate-200">{msg}</span>
                      <span className="truncate text-slate-500">{host}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="rounded-md border border-border bg-bg-elevated p-3">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-slate-500">Top MITRE</p>
                <ul className="space-y-2 text-xs">
                  {[
                    ["T1059.001","PowerShell",98],
                    ["T1003.001","LSASS Memory",92],
                    ["T1071.001","Web C2",84],
                    ["T1547.001","Run Keys",73],
                    ["T1078",    "Valid Accounts",61],
                  ].map(([id, name, w]) => (
                    <li key={id as string}>
                      <div className="flex items-baseline justify-between">
                        <span className="font-mono text-cyber-300">{id}</span>
                        <span className="text-slate-400">{name}</span>
                      </div>
                      <div className="mt-1 h-1.5 w-full overflow-hidden rounded bg-bg">
                        <div className="h-full bg-gradient-to-r from-cyber-500 to-neon-purple" style={{ width: `${w}%` }} />
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="container mx-auto max-w-7xl px-6 py-16">
        <h2 className="text-center font-mono text-3xl font-bold text-white">An entire SOC at your fingertips</h2>
        <p className="mx-auto mt-3 max-w-2xl text-center text-slate-400">
          Everything an enterprise security team uses, built into one platform.
        </p>
        <div className="mt-12 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[
            { i: DoorOpen, t: "Learning Rooms", d: "62 hands-on rooms — from zero networking knowledge to AWS, Azure, Kubernetes, and nation-state kill chains. Reading, quizzes, real log analysis, and CTF-style flags." },
            { i: LayoutDashboard, t: "SOC Dashboard", d: "A live telemetry feed across 5 companies — mostly normal activity, with a real attack hidden inside. No hints, no flashing alerts: you decide what's benign and what isn't." },
            { i: Activity, t: "EDR & SIEM Telemetry", d: "Vendor-accurate raw logs — CrowdStrike, Defender, Sentinel, Check Point, AWS CloudTrail and more — exactly the fields a real analyst reads." },
            { i: ClipboardCheck, t: "Incident Report Grading", d: "State the attack, the evidence, and the response in your own words. An AI grader checks it against ground truth and calls out anything you invented." },
            { i: Target, t: "Attack Scenarios", d: "18 full kill-chain investigations — phishing to cloud exfil, ransomware, BEC, insider threat, supply chain, Kerberoasting, and more." },
            { i: Network, t: "MITRE ATT&CK Context", d: "Every technique badge opens a plain-language explainer — tactic, technique, and why it matters to an analyst." },
            { i: BookOpen, t: "Learning Path", d: "Deep-dive reference lessons on protocols and investigation workflows, for when a Room isn't enough detail." },
            { i: ClipboardList, t: "Quizzes", d: "Knowledge checks across every topic in the curriculum, from networking basics to cloud security." },
            { i: TrendingUp, t: "XP & Progress", d: "Every task and Room earns XP. Track what you've completed and what's next across your whole learning path." },
          ].map(({ i: Icon, t, d }) => (
            <div key={t} className="group rounded-lg border border-border bg-bg-elevated/60 p-5 backdrop-blur transition hover:border-cyber-500/40 hover:bg-bg-elevated">
              <div className="mb-3 inline-flex h-10 w-10 items-center justify-center rounded-md border border-cyber-500/30 bg-cyber-500/10 text-cyber-300 transition group-hover:shadow-glow">
                <Icon className="h-5 w-5" />
              </div>
              <h3 className="font-semibold text-white">{t}</h3>
              <p className="mt-1.5 text-sm text-slate-400">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Curriculum */}
      <section id="tracks" className="container mx-auto max-w-7xl px-6 py-16">
        <h2 className="text-center font-mono text-3xl font-bold text-white">62 rooms. Zero to analyst.</h2>
        <p className="mx-auto mt-3 max-w-2xl text-center text-slate-400">
          Every room is beginner, intermediate, or advanced, and prerequisites unlock in order — no
          room ever assumes knowledge you haven't been taught yet.
        </p>
        <div className="mt-10 grid grid-cols-2 gap-4 md:grid-cols-4">
          {[
            { t: "SOC Operations",     c: "from-cyber-500/30",         n: 7 },
            { t: "Endpoint Security",  c: "from-neon-purple/30",       n: 7 },
            { t: "Cloud Security",     c: "from-severity-high/30",     n: 7 },
            { t: "Threat Detection",   c: "from-neon-green/30",        n: 7 },
            { t: "Threat Intelligence",c: "from-severity-critical/30", n: 6 },
            { t: "SIEM & Detection",   c: "from-neon-amber/30",        n: 6 },
            { t: "Network Security",   c: "from-cyber-500/30",         n: 6 },
            { t: "Plus: AWS, GCP, DLP, SOAR, Kubernetes, and more", c: "from-neon-purple/30", n: 15 },
          ].map(tr => (
            <div key={tr.t} className={`relative overflow-hidden rounded-lg border border-border bg-bg-elevated p-5`}>
              <div className={`pointer-events-none absolute inset-0 bg-gradient-to-br ${tr.c} to-transparent opacity-50`} />
              <div className="relative">
                <p className="font-mono text-sm text-cyber-300">{tr.n} rooms</p>
                <p className="mt-1 text-lg font-bold text-white">{tr.t}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      <footer className="border-t border-border py-8">
        <div className="container mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-6 text-xs text-slate-500 md:flex-row">
          <Logo size="sm" />
          <p>© 2026 HACK THE SOC · Synthetic data only · Not a replacement for production SOC tooling.</p>
        </div>
      </footer>
    </div>
  );
}
