import Link from "next/link";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/Button";
import {
  Activity, ArrowRight, BookOpen, ClipboardCheck, Cloud, Fingerprint, Lock,
  Network, Radar, ShieldCheck, Terminal, Waypoints,
} from "lucide-react";

/**
 * Landing page — the only route an anonymous visitor can reach.
 *
 * Two deliberate constraints, both from the owner:
 *  1. NO INVENTORY COUNTS. It used to lead with "62 rooms", "18 scenarios",
 *     "7 rooms" per track. Counts date instantly, invite comparison on the one
 *     axis that doesn't matter, and say nothing about what a shift here
 *     actually feels like. Every section now describes capability instead.
 *  2. ACCESS IS PAID. The old CTA read "Start Learning — it's free". Access is
 *     licensed (per-seat for individuals, cohort licences for colleges), so the
 *     CTA and the access section say so plainly rather than implying otherwise.
 *
 * Stays a Server Component: all motion is CSS (see globals.css), so the page
 * ships no JavaScript of its own.
 */

// The hero console's alert feed. One coherent intrusion told in six lines —
// Office macro → C2 → persistence → credential theft → stolen-session SSO →
// cloud exfil — so a visitor who reads security logs recognises a real kill
// chain rather than decorative noise.
const FEED: { t: string; sev: "critical" | "high"; id: string; msg: string; host: string }[] = [
  { t: "09:47:12", sev: "critical", id: "CRWD-9F3A7C12", msg: "Encoded PowerShell spawned by WINWORD.EXE", host: "WS-FIN-3041" },
  { t: "09:47:18", sev: "high",     id: "PAN-A8B12345",  msg: "Outbound TLS to telemetry-api-3a8f1.xyz", host: "WS-FIN-3041" },
  { t: "09:47:30", sev: "high",     id: "SYSMON-0001",   msg: "HKCU\\Run key 'WindowsUpdater' created", host: "WS-FIN-3041" },
  { t: "09:48:02", sev: "critical", id: "CRWD-9F3A7C5E", msg: "LSASS MiniDump via comsvcs.dll", host: "WS-FIN-3041" },
  { t: "09:51:44", sev: "high",     id: "OKTA-77BB12",   msg: "SSO from new ASN, impossible travel", host: "a.park@cryotech.io" },
  { t: "09:54:18", sev: "high",     id: "AWS-CT2278",    msg: "S3 GetObject 184MB customer-exports", host: "a.park@cryotech.io" },
];

const CAPABILITIES = [
  {
    i: Radar,
    t: "A feed that doesn't tell you where to look",
    d: "Telemetry streams across several companies at once — overwhelmingly ordinary activity, with a real intrusion moving through it. Nothing is highlighted, nothing is pre-sorted. Finding it is the exercise.",
  },
  {
    i: Terminal,
    t: "Raw logs, not screenshots of logs",
    d: "Expand any event and you get the actual field names a vendor emits — winlog.event_data, event_simpleName, aws.cloudtrail. You learn to read the source, not a tidied-up summary of it.",
  },
  {
    i: ClipboardCheck,
    t: "You write the incident report",
    d: "State the attack, the evidence, and the response in your own words. It's graded against what actually happened — cite an indicator that never appeared in the logs and you'll be told exactly which one you invented.",
  },
  {
    i: Fingerprint,
    t: "Investigate like an analyst",
    d: "Tag indicators as you find them, pivot host to user to session, and build the timeline yourself. The IOC notebook fills up from your own reading of the evidence.",
  },
  {
    i: Waypoints,
    t: "Every technique, in context",
    d: "MITRE ATT&CK mapping throughout, with plain-language explainers on the tactic, the technique, and why an analyst should care — attached to the alert where it matters, not buried in a reference table.",
  },
  {
    i: BookOpen,
    t: "Structured from zero",
    d: "Guided rooms that start below networking fundamentals and end at nation-state kill chains. Prerequisites unlock in order, so nothing ever assumes knowledge you weren't taught.",
  },
];

const SHIFT = [
  { n: "01", t: "The feed opens", d: "Alerts arrive in real time across your tenants. No triage queue, no severity sorting done for you." },
  { n: "02", t: "You investigate", d: "Open events, read raw fields, pivot between hosts and identities, tag what looks like evidence." },
  { n: "03", t: "You call it", d: "True positive, false positive, escalate — and then write the report that justifies the call." },
  { n: "04", t: "You're marked", d: "Graded against ground truth: what the attack really was, which indicators were real, what you missed." },
];

const COVERAGE = [
  { i: ShieldCheck, t: "Endpoint & EDR",       d: "Process trees, parent-child anomalies, credential dumping, isolation decisions." },
  { i: Activity,    t: "SIEM & Detection",     d: "Query languages, rule tuning, correlation, and the false-positive economics of a real SOC." },
  { i: Lock,        t: "Identity & Access",    d: "Password spray, MFA fatigue, token theft, privileged access, conditional-access failures." },
  { i: Cloud,       t: "Cloud & Container",    d: "AWS, Azure and GCP control-plane abuse, IAM escalation, storage exfiltration, Kubernetes." },
  { i: Network,     t: "Network & Perimeter",  d: "Firewall logs, DNS investigation, tunnelling, C2 channels, encrypted-traffic analysis." },
  { i: ClipboardCheck, t: "Response & Reporting", d: "Playbook execution, escalation judgement, and writing the report a manager can act on." },
];

const VENDORS = [
  "CrowdStrike Falcon", "Microsoft Defender XDR", "Microsoft Sentinel", "Splunk",
  "Elastic Security", "Wazuh", "Check Point", "Palo Alto Networks", "FortiGate",
  "Okta", "Entra ID", "AWS CloudTrail", "Microsoft Purview", "Cisco ISE",
];

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.25em] text-cyber-400/80">
      {children}
    </p>
  );
}

export default function Landing() {
  return (
    <div className="relative min-h-screen overflow-hidden">
      {/* Background grid + glow */}
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[900px] bg-cyber-grid" />
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[900px] bg-cyber-glow" />

      {/* ── Top nav ─────────────────────────────────────────────────────────── */}
      <header className="container mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
        <Logo />
        {/* In-page anchors only. The old nav deep-linked to /rooms and
            /scenarios, which are gated — every click bounced a visitor
            straight to the login screen. */}
        <nav className="hidden items-center gap-7 text-sm text-slate-300 md:flex">
          <a href="#shift" className="transition hover:text-cyber-300">The shift</a>
          <a href="#platform" className="transition hover:text-cyber-300">Platform</a>
          <a href="#coverage" className="transition hover:text-cyber-300">Coverage</a>
          <a href="#access" className="transition hover:text-cyber-300">Access</a>
        </nav>
        <div className="flex items-center gap-3">
          <Link href="/login" className="hidden text-sm text-slate-300 transition hover:text-cyber-300 sm:block">
            Sign in
          </Link>
          <Link href="#access">
            <Button variant="primary">Get access</Button>
          </Link>
        </div>
      </header>

      {/* ── Hero ────────────────────────────────────────────────────────────── */}
      <section id="main-content" className="container mx-auto max-w-7xl px-6 pb-8 pt-12 md:pt-20">
        <div className="mx-auto max-w-3xl text-center">
          <div className="rise-in inline-flex items-center gap-2 rounded-full border border-cyber-500/30 bg-cyber-500/5 px-3 py-1 text-xs">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon-green opacity-75" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-neon-green" />
            </span>
            <span className="font-mono font-semibold uppercase tracking-[0.2em] text-cyber-200">
              Live SOC simulation
            </span>
          </div>

          <h1
            className="rise-in mt-7 font-mono text-5xl font-extrabold leading-[1.05] tracking-tight text-white md:text-7xl"
            style={{ animationDelay: "80ms" }}
          >
            <span className="text-glow">HACK</span>{" "}
            <span className="text-cyber-400 text-glow">THE</span>{" "}
            <span className="text-glow">SOC</span>
          </h1>

          <p
            className="rise-in mx-auto mt-6 max-w-2xl text-balance text-lg leading-relaxed text-slate-300 md:text-xl"
            style={{ animationDelay: "160ms" }}
          >
            Most training hands you a labelled alert and asks what it is.
            <span className="text-white"> This hands you the whole feed and asks what&apos;s wrong with it.</span>
          </p>

          <p
            className="rise-in mx-auto mt-4 max-w-2xl text-balance text-sm leading-relaxed text-slate-400 md:text-base"
            style={{ animationDelay: "220ms" }}
          >
            Real vendor telemetry. A live intrusion buried in ordinary traffic. No hints, no
            highlighting — you investigate, you decide, you write the report, and it gets marked
            against what actually happened.
          </p>

          <div
            className="rise-in mt-9 flex flex-wrap items-center justify-center gap-3"
            style={{ animationDelay: "300ms" }}
          >
            <Link href="#access">
              <Button size="lg" variant="primary">
                Get access <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
            <Link href="/login">
              <Button size="lg" variant="outline">Sign in</Button>
            </Link>
          </div>
          <p className="rise-in mt-4 text-xs text-slate-500" style={{ animationDelay: "340ms" }}>
            Licensed access · Individual seats and cohort licences for colleges
          </p>
        </div>

        {/* Console preview */}
        <div
          className="rise-in console-sweep relative mx-auto mt-16 max-w-6xl overflow-hidden rounded-xl border border-border bg-bg-elevated/60 p-2 shadow-glow backdrop-blur"
          style={{ animationDelay: "380ms" }}
        >
          <div className="rounded-lg border border-border bg-bg p-4 md:p-6">
            {/* Console chrome */}
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-3">
                <span className="h-2.5 w-2.5 rounded-full bg-severity-critical" />
                <span className="h-2.5 w-2.5 rounded-full bg-severity-medium" />
                <span className="h-2.5 w-2.5 rounded-full bg-neon-green" />
                <span className="ml-3 font-mono text-xs text-slate-400">soc.cryotech.io / live</span>
              </div>
              <span className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest text-slate-400">
                <span className="relative flex h-1.5 w-1.5">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-severity-critical opacity-75" />
                  <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-severity-critical" />
                </span>
                streaming
              </span>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
              {/* Alert feed */}
              <div className="rounded-md border border-border bg-bg-elevated p-3 lg:col-span-2">
                <p className="mb-2 font-mono text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                  Live alert feed
                </p>
                <ul className="space-y-0 font-mono text-[11px] md:text-xs">
                  {FEED.map((row, i) => (
                    <li
                      key={row.id}
                      className="rise-in grid grid-cols-[52px_64px_1fr] gap-2 border-b border-border/50 py-1.5 text-slate-300 last:border-0 md:grid-cols-[56px_68px_118px_1fr_130px]"
                      style={{ animationDelay: `${700 + i * 130}ms` }}
                    >
                      <span className="text-slate-500">{row.t}</span>
                      <span className={row.sev === "critical" ? "text-severity-critical" : "text-severity-high"}>
                        {row.sev.toUpperCase()}
                      </span>
                      <span className="hidden text-cyber-300 md:block">{row.id}</span>
                      <span className="truncate text-slate-200">{row.msg}</span>
                      <span className="hidden truncate text-slate-400 md:block">{row.host}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-3 border-t border-border/50 pt-2.5 font-mono text-[10px] text-slate-500">
                  Six of these belong to the same intrusion. The rest of the shift doesn&apos;t.
                </p>
              </div>

              {/* Analyst-side panel */}
              <div className="flex flex-col gap-3">
                <div className="rounded-md border border-border bg-bg-elevated p-3">
                  <p className="mb-2.5 font-mono text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                    Your verdict
                  </p>
                  <div className="space-y-1.5">
                    {[
                      { l: "True positive", c: "border-severity-critical/50 bg-severity-critical/10 text-severity-critical" },
                      { l: "False positive", c: "border-border bg-bg text-slate-500" },
                      { l: "Escalate to Tier 2", c: "border-border bg-bg text-slate-500" },
                    ].map(v => (
                      <div key={v.l} className={`rounded border px-2.5 py-1.5 text-[11px] font-semibold ${v.c}`}>
                        {v.l}
                      </div>
                    ))}
                  </div>
                </div>
                <div className="flex-1 rounded-md border border-border bg-bg-elevated p-3">
                  <p className="mb-2 font-mono text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                    IOC notebook
                  </p>
                  <ul className="space-y-1.5 font-mono text-[10px]">
                    {[
                      ["HOST", "WS-FIN-3041", "text-cyber-300"],
                      ["DOMAIN", "telemetry-api-3a8f1.xyz", "text-neon-amber"],
                      ["USER", "a.park@cryotech.io", "text-neon-purple"],
                      ["TTP", "T1003.001", "text-neon-green"],
                    ].map(([k, v, c]) => (
                      <li key={v} className="flex items-baseline gap-2">
                        <span className="w-[52px] shrink-0 text-slate-500">{k}</span>
                        <span className={`truncate ${c}`}>{v}</span>
                      </li>
                    ))}
                  </ul>
                  <p className="mt-3 border-t border-border/50 pt-2 text-[10px] leading-relaxed text-slate-500">
                    Tagged by you, as you read the evidence.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── The shift ───────────────────────────────────────────────────────── */}
      <section id="shift" className="container mx-auto max-w-7xl px-6 py-24">
        <div className="mx-auto max-w-2xl text-center">
          <SectionLabel>// How a shift runs</SectionLabel>
          <h2 className="mt-4 font-mono text-3xl font-bold text-white md:text-4xl">
            Nobody tells you which alert matters
          </h2>
          <p className="mt-4 text-slate-400">
            The loop is the same one a Tier-1 analyst runs every day — and it ends the way a real
            one does, with something you wrote being judged on whether it holds up.
          </p>
        </div>

        {/* Numbered because this genuinely is a sequence — each step consumes
            the previous step's output. */}
        <ol className="mt-14 grid grid-cols-1 gap-px overflow-hidden rounded-xl border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
          {SHIFT.map(s => (
            <li key={s.n} className="group bg-bg-elevated p-6 transition hover:bg-bg-hover">
              <span className="font-mono text-2xl font-bold text-cyber-500/40 transition group-hover:text-cyber-400">
                {s.n}
              </span>
              <h3 className="mt-3 font-semibold text-white">{s.t}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-400">{s.d}</p>
            </li>
          ))}
        </ol>
      </section>

      {/* ── Platform capabilities ───────────────────────────────────────────── */}
      <section id="platform" className="container mx-auto max-w-7xl px-6 py-24">
        <div className="mx-auto max-w-2xl text-center">
          <SectionLabel>// What&apos;s inside</SectionLabel>
          <h2 className="mt-4 font-mono text-3xl font-bold text-white md:text-4xl">
            An entire SOC, and the judgement to work in one
          </h2>
          <p className="mt-4 text-slate-400">
            The tooling is only half of it. The other half is being made to reason without a safety
            net, over and over, until it&apos;s a habit.
          </p>
        </div>

        <div className="mt-14 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {CAPABILITIES.map(({ i: Icon, t, d }) => (
            <div
              key={t}
              className="group relative overflow-hidden rounded-lg border border-border bg-bg-elevated/60 p-6 backdrop-blur transition hover:border-cyber-500/40 hover:bg-bg-elevated"
            >
              <div className="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-md border border-cyber-500/30 bg-cyber-500/10 text-cyber-300 transition group-hover:shadow-glow">
                <Icon className="h-5 w-5" />
              </div>
              <h3 className="font-semibold leading-snug text-white">{t}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-400">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Telemetry sources ───────────────────────────────────────────────── */}
      <section className="container mx-auto max-w-7xl px-6 py-16">
        <div className="rounded-xl border border-border bg-bg-elevated/40 p-8 backdrop-blur md:p-12">
          <div className="grid grid-cols-1 gap-10 lg:grid-cols-[1fr_1.15fr] lg:items-center">
            <div>
              <SectionLabel>// The telemetry</SectionLabel>
              <h2 className="mt-4 font-mono text-2xl font-bold leading-tight text-white md:text-3xl">
                The field names are the real field names
              </h2>
              <p className="mt-4 text-sm leading-relaxed text-slate-400">
                Every event is modelled on what the product actually emits, down to the schema. When
                you later open a genuine console, nothing about it is unfamiliar — you have been
                reading its output all along.
              </p>
              <div className="mt-6 flex flex-wrap gap-2">
                {VENDORS.map(v => (
                  <span
                    key={v}
                    className="rounded-full border border-border bg-bg px-3 py-1 font-mono text-[11px] text-slate-400 transition hover:border-cyber-500/40 hover:text-cyber-300"
                  >
                    {v}
                  </span>
                ))}
              </div>
            </div>

            {/* A real-shaped raw event, the way the platform renders one. */}
            <div className="overflow-hidden rounded-lg border border-border bg-bg">
              <div className="flex items-center gap-2 border-b border-border bg-bg-elevated/60 px-4 py-2.5">
                <span className="rounded border border-neon-amber/40 bg-neon-amber/10 px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider text-neon-amber">
                  EDR
                </span>
                <span className="font-mono text-[11px] text-slate-300">ProcessRollup2</span>
                <span className="ml-auto font-mono text-[10px] text-slate-500">raw fields</span>
              </div>
              <div className="overflow-x-auto p-4">
                <table className="w-full font-mono text-[11px]">
                  <tbody>
                    {[
                      ["event_simpleName", "ProcessRollup2"],
                      ["ParentBaseFileName", "WINWORD.EXE"],
                      ["FileName", "powershell.exe"],
                      ["CommandLine", "-nop -w hidden -enc SQBFAF..."],
                      ["SHA256HashData", "9f3a7c12e8b4...d21a"],
                      ["SeverityName", "Critical"],
                      ["ComputerName", "WS-FIN-3041"],
                    ].map(([k, v]) => (
                      <tr key={k} className="border-b border-border/40 last:border-0">
                        <td className="whitespace-nowrap py-1.5 pr-5 align-top text-cyber-300">{k}</td>
                        <td className="break-all py-1.5 text-slate-300">{v}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Coverage ────────────────────────────────────────────────────────── */}
      <section id="coverage" className="container mx-auto max-w-7xl px-6 py-24">
        <div className="mx-auto max-w-2xl text-center">
          <SectionLabel>// Coverage</SectionLabel>
          <h2 className="mt-4 font-mono text-3xl font-bold text-white md:text-4xl">
            From first principles to nation-state
          </h2>
          <p className="mt-4 text-slate-400">
            Built as one ordered path, not a library to browse. Each domain assumes only what the
            path has already taught you.
          </p>
        </div>

        <div className="mt-14 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {COVERAGE.map(({ i: Icon, t, d }) => (
            <div key={t} className="flex gap-4 rounded-lg border border-border bg-bg-elevated/50 p-5 transition hover:border-cyber-500/30">
              <Icon className="mt-0.5 h-5 w-5 shrink-0 text-cyber-400" />
              <div>
                <h3 className="font-semibold text-white">{t}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-slate-400">{d}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Access ──────────────────────────────────────────────────────────── */}
      <section id="access" className="container mx-auto max-w-7xl px-6 py-24">
        <div className="rule-fade mx-auto mb-16 max-w-3xl" />

        <div className="mx-auto max-w-2xl text-center">
          <SectionLabel>// Access</SectionLabel>
          <h2 className="mt-4 font-mono text-3xl font-bold text-white md:text-4xl">
            This one isn&apos;t free
          </h2>
          <p className="mt-4 text-slate-400">
            Building an intrusion that survives an analyst&apos;s scrutiny takes real work, and it
            gets rebuilt as the tradecraft moves. Access is licensed, and every seat is a real seat.
          </p>
        </div>

        <div className="mx-auto mt-14 grid max-w-4xl grid-cols-1 gap-5 md:grid-cols-2">
          {/* Individual */}
          <div className="relative overflow-hidden rounded-xl border border-cyber-500/40 bg-bg-elevated p-7 shadow-glow">
            <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-cyber-500/10 to-transparent" />
            <div className="relative">
              <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-cyber-300">
                Analyst seat
              </p>
              <h3 className="mt-3 text-xl font-bold text-white">For individuals</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-400">
                Full access to the live console, the guided path, and graded incident reporting —
                one analyst, one seat.
              </p>
              <ul className="mt-5 space-y-2.5 text-sm text-slate-300">
                {[
                  "The live SOC console and every attack scenario",
                  "The full guided curriculum, start to finish",
                  "AI-graded incident reports with ground-truth feedback",
                  "Progress, XP and rank tracked across everything",
                ].map(f => (
                  <li key={f} className="flex gap-2.5">
                    <span className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full bg-cyber-400" />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
              <Link href="/signup" className="mt-7 block">
                <Button size="lg" variant="primary" className="w-full">
                  Get access <ArrowRight className="h-4 w-4" />
                </Button>
              </Link>
              <p className="mt-3 text-center text-xs text-slate-500">
                Already licensed? <Link href="/login" className="text-cyber-300 underline-offset-2 hover:underline">Sign in</Link>
              </p>
            </div>
          </div>

          {/* Cohort */}
          <div className="rounded-xl border border-border bg-bg-elevated/60 p-7">
            <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-neon-purple">
              Cohort licence
            </p>
            <h3 className="mt-3 text-xl font-bold text-white">For colleges &amp; teams</h3>
            <p className="mt-2 text-sm leading-relaxed text-slate-400">
              Your own isolated tenant, your roster, your reporting — for training a class or a
              security team together.
            </p>
            <ul className="mt-5 space-y-2.5 text-sm text-slate-300">
              {[
                "A private organisation, isolated from every other tenant",
                "Instructor console: assignments, due dates, per-student drill-down",
                "Class leaderboard and exportable grades",
                "Seat provisioning and invite links you control",
              ].map(f => (
                <li key={f} className="flex gap-2.5">
                  <span className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full bg-neon-purple" />
                  <span>{f}</span>
                </li>
              ))}
            </ul>
            <Link href="/join" className="mt-7 block">
              <Button size="lg" variant="secondary" className="w-full">
                I have an invite code
              </Button>
            </Link>
            <p className="mt-3 text-center text-xs text-slate-500">
              Licensing a cohort is arranged directly — talk to us first.
            </p>
          </div>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────────────────────── */}
      <footer className="border-t border-border py-8">
        <div className="container mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-6 text-xs text-slate-400 md:flex-row">
          <Logo size="sm" />
          <p>© 2026 HACK THE SOC · Synthetic data only · Not a replacement for production SOC tooling.</p>
          <div className="flex items-center gap-4">
            <Link href="/privacy" className="text-slate-400 underline-offset-2 hover:text-cyber-300 hover:underline">
              Privacy &amp; data
            </Link>
            <Link href="/accessibility" className="text-slate-400 underline-offset-2 hover:text-cyber-300 hover:underline">
              Accessibility
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
