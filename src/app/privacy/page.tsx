import Link from "next/link";
import { ArrowLeft } from "lucide-react";

export const metadata = {
  title: "Privacy & Data — HACK THE SOC",
  description: "What data HACK THE SOC stores, why, and who processes it.",
};

// Public, static content page. Deliberately plain and honest — it exists to
// satisfy the transparency duty toward data subjects (יידוע נושא המידע) under
// תקנות הגנת הפרטיות, and to disclose the third-party AI sub-processors that
// grade free-text answers.
export default function PrivacyPage() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-16 text-slate-300">
      <Link href="/" className="mb-8 inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyber-300">
        <ArrowLeft className="h-4 w-4" /> Back
      </Link>

      <h1 className="mb-2 text-3xl font-bold text-white">Privacy &amp; Data</h1>
      <p className="mb-10 text-sm text-slate-400">Last updated: 22 July 2026</p>

      <div className="space-y-8 leading-relaxed">
        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">What we store</h2>
          <p>
            HACK THE SOC is a training platform. When you create an account we store your
            <strong className="text-white"> email address</strong>, your chosen
            <strong className="text-white"> nickname (handle)</strong> and display name, and your
            <strong className="text-white"> learning progress</strong> — completed rooms and
            scenarios, scores, XP, and streak. That is the whole of it. We do not collect
            sensitive information (health, financial, biometric, political, or similar), and the
            attack data you investigate in the product is entirely <strong className="text-white">synthetic</strong>.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">Why we store it</h2>
          <p>
            Only to run the service: to sign you in, to remember where you are in the curriculum,
            and to show your rank and progress. We do not sell data, and we do not use it to build
            advertising profiles.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">Who processes it (sub-processors)</h2>
          <ul className="ml-5 list-disc space-y-2">
            <li>
              <strong className="text-white">Supabase</strong> — hosts the database and handles
              authentication (your account and progress).
            </li>
            <li>
              <strong className="text-white">Vercel</strong> — hosts and serves the application.
            </li>
            <li>
              <strong className="text-white">AI grading providers (Anthropic / OpenAI)</strong> —
              when you submit a free-text answer or incident report for AI feedback, the
              <em> text of that answer</em> is sent to the provider to generate the grade. Write
              your reports about the synthetic scenario only; there is no need to include real
              personal information, and you should not. Your identity is not sent with the text.
            </li>
          </ul>
        </section>

        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">Your rights</h2>
          <p>
            You may request access to, correction of, or deletion of your account data. Contact the
            platform owner to exercise these rights. Under Israeli privacy law (חוק הגנת הפרטיות
            והתקנות מכוחו, כולל תיקון 13), you have the right to know what is held about you and to
            have it corrected or removed.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">Security</h2>
          <p>
            Access to your account is protected by authentication, row-level database access
            controls, and an audit trail of privileged actions. Data is transmitted over HTTPS.
            No system is perfectly secure; if we ever become aware of a security event affecting
            your data, we will act on our obligations to notify as required by law.
          </p>
        </section>
      </div>
    </main>
  );
}
