"use client";
/**
 * Content-feedback triage inbox (platform admin). The body is the shared
 * FeedbackInbox component, also used by the super-admin console.
 */
import { Topbar } from "@/components/nav/Topbar";
import { FeedbackInbox } from "@/components/feedback/FeedbackInbox";

export default function AdminFeedbackPage() {
  return (
    <div>
      <Topbar title="Content feedback" subtitle="What students reported as wrong, confusing or broken" />
      <div className="container mx-auto max-w-[1000px] px-6 py-6">
        <FeedbackInbox />
      </div>
    </div>
  );
}
