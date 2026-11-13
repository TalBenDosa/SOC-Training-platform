import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { getRequestBrand } from "@/lib/brand/server";
import { PLATFORM_NAME } from "@/lib/brand/brand";
import { Logo } from "@/components/Logo";
import { buttonClasses } from "@/components/ui/Button";
import { DemoRequestForm } from "@/components/demo/DemoRequestForm";
import { bookingUrl } from "@/lib/demo/demoRequest";
import { ArrowDown, Building2, GraduationCap, Radar, ShieldCheck, Swords, Users } from "lucide-react";

export const metadata: Metadata = {
  title: "Book a demo", // the root layout's template adds the platform name
  description: "See a live SOC shift, the team exercise and the instructor console in a 30-minute walkthrough.",
};

/**
 * Book a demo (Tal, 2026-11-13): the page the home page and the sign-in page point to. A visitor sees what the
 * walkthrough covers and asks for one; the request is emailed to the owner (src/app/api/demo-request). No
 * inventory counts (owner rule): the page describes what a session is like, not how much content exists.
 */
const COVERS = [
  { i: Radar, t: "A live shift on the analyst dashboard", d: "The feed, the raw vendor logs, the EDR investigation and the graded incident report, on one of the training companies." },
  { i: Swords, t: "A team exercise", d: "Tier-1, Tier-2 and a shift manager working one incident together, the attacks the instructor picks, and the after-action report." },
  { i: GraduationCap, t: "The learning path", d: "Guided rooms from networking basics to cloud and identity attacks, and how practice and theory meet." },
  { i: ShieldCheck, t: "Your environment and reporting", d: "A private environment for your organization, cohorts and assignments, per-learner progress and exportable grades." },
];

const AUDIENCES = [
  { i: GraduationCap, t: "Colleges and universities", d: "A practical SOC track for cyber programs, with instructor tools built in." },
  { i: Users, t: "Training providers", d: "Hands-on analyst training your cohorts run on real vendor telemetry." },
  { i: Building2, t: "SOC teams and MSSPs", d: "Onboard new analysts and drill the team on incidents before they meet them for real." },
];

export default async function DemoPage() {
  // A white-label organization's domain is that organization's front door: no HACK THE SOC sales page there.
  if ((await getRequestBrand()).whiteLabel) redirect("/login");
  const calendar = bookingUrl(process.env.DEMO_BOOKING_URL);
  return (
    <div className="relative min-h-screen overflow-hidden">
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[800px] bg-cyber-grid" />
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[800px] bg-cyber-glow" />

      <header className="container mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
        <Link href="/" aria-label={`${PLATFORM_NAME} home`}><Logo /></Link>
        <div className="flex items-center gap-3">
          <Link href="/login" className="hidden whitespace-nowrap text-sm text-slate-300 transition hover:text-cyber-300 sm:block">Sign in</Link>
          <Link href="/join" className={buttonClasses("outline", "md", "whitespace-nowrap")}>Get access</Link>
        </div>
      </header>

      <main id="main-content" className="container mx-auto max-w-7xl px-6 pb-20 pt-6">
        <div className="grid items-start gap-12 lg:grid-cols-[1fr_minmax(0,30rem)]">
          <section aria-labelledby="demo-title">
            <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.25em] text-cyber-400/80">Book a demo</p>
            <h1 id="demo-title" className="mt-4 text-balance font-mono text-4xl font-extrabold leading-tight tracking-tight text-white md:text-5xl">
              See a SOC shift before you commit to one
            </h1>
            <p className="mt-5 max-w-xl text-pretty text-base leading-relaxed text-slate-300 md:text-lg">
              A 30-minute walkthrough with the team behind {PLATFORM_NAME}. We run a live session on the platform, answer your
              questions about your program or your team, and explain how licensing works for you.
            </p>
            {/* On a phone the form sits below everything else: one tap takes the visitor straight to it. */}
            <a href="#request" className={buttonClasses("primary", "lg", "mt-6 lg:hidden")}>
              Request your demo <ArrowDown className="h-4 w-4" aria-hidden="true" />
            </a>

            <h2 className="mt-10 text-sm font-bold uppercase tracking-wider text-slate-400">What the demo covers</h2>
            <ul className="mt-4 grid gap-4 sm:grid-cols-2">
              {COVERS.map(({ i: Icon, t, d }) => (
                <li key={t} className="rounded-lg border border-border bg-bg-elevated/60 p-4">
                  <Icon className="h-5 w-5 text-cyber-400" aria-hidden="true" />
                  <p className="mt-2 text-sm font-semibold text-white">{t}</p>
                  <p className="mt-1 text-sm leading-relaxed text-slate-400">{d}</p>
                </li>
              ))}
            </ul>

            <h2 className="mt-10 text-sm font-bold uppercase tracking-wider text-slate-400">Who it&apos;s for</h2>
            <ul className="mt-4 space-y-3">
              {AUDIENCES.map(({ i: Icon, t, d }) => (
                <li key={t} className="flex gap-3">
                  <Icon className="mt-0.5 h-5 w-5 shrink-0 text-cyber-400" aria-hidden="true" />
                  <p className="text-sm leading-relaxed text-slate-300"><span className="font-semibold text-white">{t}.</span> {d}</p>
                </li>
              ))}
            </ul>
          </section>

          <section id="request" aria-labelledby="demo-form-title" className="scroll-mt-6 rounded-2xl border border-border bg-bg-elevated p-6 shadow-2xl lg:sticky lg:top-6">
            <h2 id="demo-form-title" className="text-lg font-bold text-white">Request your demo</h2>
            <p className="mb-5 mt-1 text-sm text-slate-400">We reply within one business day to set a time.</p>
            <DemoRequestForm bookingUrl={calendar} />
          </section>
        </div>
      </main>

      <footer className="border-t border-border py-8">
        <div className="container mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6 text-xs text-slate-400">
          <p>© 2026 {PLATFORM_NAME} · Synthetic data only</p>
          <div className="flex items-center gap-4">
            <Link href="/privacy" className="underline underline-offset-2 hover:text-cyber-300">Privacy &amp; data</Link>
            <Link href="/accessibility" className="underline underline-offset-2 hover:text-cyber-300">Accessibility</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
