import Link from "next/link";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Mail, Lock, ArrowRight, ShieldCheck } from "lucide-react";

export const metadata = { title: "Sign in" };

export default function LoginPage() {
  return (
    <div className="relative min-h-screen overflow-hidden">
      <div className="pointer-events-none absolute inset-0 -z-10 bg-cyber-grid" />
      <div className="pointer-events-none absolute inset-0 -z-10 bg-cyber-glow" />

      <div className="container mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
        <Logo />
        <Link href="/" className="text-sm text-slate-300 hover:text-cyber-300">← Back</Link>
      </div>

      <div className="container mx-auto grid max-w-6xl grid-cols-1 gap-10 px-6 py-12 lg:grid-cols-2 lg:py-20">
        <div className="hidden flex-col justify-center lg:flex">
          <div className="inline-flex w-fit items-center gap-2 rounded-full border border-cyber-500/30 bg-cyber-500/5 px-3 py-1 text-xs">
            <ShieldCheck className="h-3.5 w-3.5 text-cyber-300" />
            <span className="font-semibold uppercase tracking-widest text-cyber-200">Live SOC simulation</span>
          </div>
          <h1 className="mt-4 font-mono text-4xl font-bold leading-tight text-white">
            Step into the SOC.<br />Defend like it's real.
          </h1>
          <p className="mt-4 max-w-md text-slate-400">
            Sign in to continue your training. Your alerts, hunts, and investigations are saved to your analyst profile.
          </p>
          <ul className="mt-8 space-y-2 text-sm text-slate-400">
            {[
              "Triage real-feeling EDR alerts",
              "Map TTPs to MITRE ATT&CK",
              "Hunt with KQL / SPL / Sigma",
              "Get explained answers from the AI Co-Analyst",
            ].map(t => (
              <li key={t} className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-cyber-400" />
                {t}
              </li>
            ))}
          </ul>
        </div>

        <div className="rounded-xl border border-border bg-bg-elevated/60 p-6 backdrop-blur shadow-glow">
          <h2 className="font-mono text-2xl font-bold text-white">Sign in</h2>
          <p className="mt-1 text-sm text-slate-400">Or <Link href="/signup" className="text-cyber-300 hover:text-cyber-200">create your analyst account</Link></p>

          <form className="mt-6 space-y-4">
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">Email</span>
              <div className="relative mt-1">
                <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <Input type="email" name="email" placeholder="analyst@company.com" className="pl-9" />
              </div>
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">Password</span>
              <div className="relative mt-1">
                <Lock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <Input type="password" name="password" placeholder="••••••••" className="pl-9" />
              </div>
            </label>
            <Button className="w-full" size="lg" type="submit">Continue <ArrowRight className="h-4 w-4" /></Button>
          </form>

          <div className="my-5 flex items-center gap-3 text-[10px] uppercase tracking-widest text-slate-500">
            <div className="h-px flex-1 bg-border" /> or <div className="h-px flex-1 bg-border" />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Button variant="secondary">Continue with Google</Button>
            <Button variant="secondary">Continue with Okta</Button>
          </div>
          <p className="mt-6 text-[11px] text-slate-500">
            By signing in, you agree to operate the SOC against synthetic data only. No real customer data is ever ingested.
          </p>
        </div>
      </div>
    </div>
  );
}
