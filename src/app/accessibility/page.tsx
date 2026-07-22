import Link from "next/link";
import { ArrowLeft } from "lucide-react";

export const metadata = {
  title: "Accessibility Statement — HACK THE SOC",
  description: "Our accessibility commitment, the standard we target, known limitations, and how to reach us.",
};

// Public accessibility statement (הצהרת נגישות) — a standalone requirement under
// the Israeli Equal Rights for Persons with Disabilities regulations. It states
// the target standard, what was done, known limitations, and a contact route.
//
// IMPORTANT (owner action): fill in the real accessibility-contact details and,
// if the service targets the Israeli public, add a Hebrew version. Do not claim
// full conformance until a certified accessibility auditor (מורשה נגישות שירות)
// has verified it — this page deliberately states "we aim to conform" + known
// limitations rather than asserting compliance.
export default function AccessibilityPage() {
  return (
    <main id="main-content" className="mx-auto max-w-3xl px-6 py-16 text-slate-300">
      <Link href="/" className="mb-8 inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyber-300">
        <ArrowLeft className="h-4 w-4" /> Back
      </Link>

      <h1 className="mb-2 text-3xl font-bold text-white">Accessibility Statement</h1>
      <p className="mb-10 text-sm text-slate-400">Last updated: 22 July 2026</p>

      <div className="space-y-8 leading-relaxed">
        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">Our commitment</h2>
          <p>
            We want HACK THE SOC to be usable by everyone, including people who rely on
            assistive technology. We aim to conform to <strong className="text-white">Israeli
            Standard IS 5568</strong>, which is based on the international
            <strong className="text-white"> WCAG 2.0 level AA</strong> guidelines (and we work
            toward WCAG 2.1 AA), in line with the Equal Rights for Persons with Disabilities
            (Accessibility Adjustments to Service) Regulations.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">What we have done</h2>
          <ul className="ml-5 list-disc space-y-2">
            <li>Semantic structure with landmarks and headings, and a &ldquo;skip to content&rdquo; link.</li>
            <li>Form fields with programmatically associated labels.</li>
            <li>Visible keyboard focus on interactive elements, and keyboard operability.</li>
            <li>Respect for the operating-system &ldquo;reduce motion&rdquo; setting.</li>
            <li>Descriptive page titles and support for browser zoom.</li>
          </ul>
        </section>

        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">Known limitations</h2>
          <p>
            Accessibility is an ongoing effort. We are still improving color-contrast in some
            secondary text, and we have not yet completed a full review with screen readers
            (NVDA / VoiceOver). If you encounter a barrier that is not listed here, please tell
            us — it helps us prioritize.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">Contact us about accessibility</h2>
          <p>
            If you have trouble using any part of the service, or want to report an accessibility
            problem, contact the platform&rsquo;s accessibility contact:
          </p>
          <ul className="ml-5 mt-2 list-disc space-y-1 text-slate-400">
            <li>Accessibility contact: <span className="text-white">[add name / role]</span></li>
            <li>Email: <span className="text-white">[add email]</span></li>
            <li>Phone: <span className="text-white">[add phone]</span></li>
          </ul>
          <p className="mt-2 text-sm text-slate-400">
            We will do our best to respond and to provide the information or service through an
            accessible channel.
          </p>
        </section>
      </div>
    </main>
  );
}
