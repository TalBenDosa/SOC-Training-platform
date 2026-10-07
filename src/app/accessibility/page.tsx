import Link from "next/link";
import { ArrowLeft } from "lucide-react";

export const metadata = {
  title: "Accessibility Statement",
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
      <p className="mb-10 text-sm text-slate-400">Last updated: 7 October 2026</p>

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
            <li>Semantic structure with landmarks and headings, and a &ldquo;skip to content&rdquo; link on every page.</li>
            <li>A unique, descriptive title for every page, and full support for browser zoom (no zoom lock).</li>
            <li>Form fields with programmatically associated labels and visible hints; validation errors and success messages are announced to screen readers.</li>
            <li>A clearly visible keyboard-focus outline on every interactive element; dialogs and menus can be closed with Escape and return focus to where you were.</li>
            <li>Text and form-field borders meet WCAG AA contrast ratios on the platform&rsquo;s dark theme.</li>
            <li>Results and states are shown with text and icons, not by color alone.</li>
            <li>Every Learning Path explainer video has subtitles in English, Hebrew and Spanish.</li>
            <li>Respect for the operating-system &ldquo;reduce motion&rdquo; setting.</li>
          </ul>
        </section>

        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">Known limitations</h2>
          <p>
            Accessibility is an ongoing effort. Some parts of the platform reproduce the dense,
            real-time consoles a SOC analyst works in, and are harder to use with assistive
            technology:
          </p>
          <ul className="ml-5 mt-2 list-disc space-y-2">
            <li>The live SOC event feed updates continuously; new events are not read out one by one, so that a screen reader is not flooded.</li>
            <li>The EDR process tree and the simulated response shell are visual, keyboard-operable tools that have not yet been fully optimised for screen readers.</li>
            <li>Raw log samples are shown exactly as the source system writes them (long JSON / syslog lines).</li>
          </ul>
          <p className="mt-2">
            We have not yet completed a full review with screen readers (NVDA / VoiceOver). If any
            of these limits stops you from completing a task, contact us and we will provide the
            content in another accessible way. If you meet a barrier that is not listed here,
            please tell us too — it helps us prioritize.
          </p>
        </section>

        <section>
          <h2 className="mb-2 text-xl font-semibold text-white">Contact us about accessibility</h2>
          <p>
            If you have trouble using any part of the service, or want to report an accessibility
            problem, contact the platform&rsquo;s accessibility contact:
          </p>
          <ul className="ml-5 mt-2 list-disc space-y-1 text-slate-400">
            <li>Accessibility contact: Tal Ben Dosa</li>
            <li>Email: <a href="mailto:tal14997@gmail.com" className="text-cyber-300 underline underline-offset-2">tal14997@gmail.com</a></li>
          </ul>
          <p className="mt-2 text-sm text-slate-400">
            Please describe the page and what you were trying to do. We aim to reply within
            5 business days and to provide the information or service through an accessible channel.
          </p>
        </section>
      </div>
    </main>
  );
}
