import Link from "next/link";
import { ArrowLeft } from "lucide-react";

export const metadata = {
  title: "Privacy & Data",
  description: "What data HACK THE SOC stores, why, and who processes it.",
};

/**
 * Rendered per request rather than prerendered, ONLY because of
 * PRIVACY_CONTACT_EMAIL below.
 *
 * As a static page, that env var is read once during `next build` and baked
 * into the HTML. Changing the address in the host's dashboard then does
 * nothing until a full rebuild — and a "Redeploy" that reuses the build cache
 * is not one. The failure is silent and in the worst possible place: the page
 * keeps publishing a stale contact address for a legally required channel,
 * while the dashboard shows the new value and everything looks correct.
 *
 * The cost is one server render of a small static page. The benefit is that
 * the published address always matches the configured one.
 */
export const dynamic = "force-dynamic";

// Public, static content page. Deliberately plain and honest — it exists to
// satisfy the transparency duty toward data subjects (יידוע נושא המידע) under
// תקנות הגנת הפרטיות, and to disclose the third-party AI sub-processors that
// grade free-text answers.
export default function PrivacyPage() {
  // Server Component, so this reads at render time and never reaches the client
  // bundle. Left unset deliberately in dev: publishing a wrong or personal
  // address on a public page is worse than routing requests through the course
  // administrator, which is the real channel for a B2B/college deployment
  // anyway. Set PRIVACY_CONTACT_EMAIL in production to offer a direct route.
  const contactEmail = process.env.PRIVACY_CONTACT_EMAIL?.trim();

  return (
    <main id="main-content" className="mx-auto max-w-3xl px-6 py-16 text-slate-300">
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
          <h2 className="mb-2 text-xl font-semibold text-white">How long we keep it</h2>
          <p>
            Account and progress data is kept for as long as your account is active, and is removed
            when your account or your institution&apos;s licence is closed. Records of privileged
            administrative actions (the audit trail) are kept for at least{" "}
            <strong className="text-white">24 months</strong>, which is the retention the Israeli
            Privacy Protection (Information Security) Regulations require for access records.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">Your rights</h2>
          <p>
            Under Israeli privacy law (חוק הגנת הפרטיות והתקנות מכוחו, כולל תיקון 13) you have the
            right to know what is held about you, and to have it corrected or deleted. We answer
            such requests within <strong className="text-white">30 days</strong>.
          </p>
          <p className="mt-3">
            To exercise them:{" "}
            {contactEmail ? (
              <>
                write to{" "}
                <a href={`mailto:${contactEmail}`} className="text-cyber-300 hover:underline">
                  {contactEmail}
                </a>
                . If you study through a college or employer, you can also ask your course
                administrator, who can act on your account directly.
              </>
            ) : (
              <>
                contact your course administrator — the person who issued your invitation. They
                administer your institution&apos;s accounts and can action access, correction and
                deletion requests, escalating to the platform operator where needed.
              </>
            )}
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
