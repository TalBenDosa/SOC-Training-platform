"use client";
/**
 * Super-admin reports inbox — every content-feedback and technical problem
 * report across all tenants, in one place. Same triage body as the platform
 * admin page; the super-admin reaches it from the Main-environment control tower.
 */
import Link from "next/link";
import { ChevronLeft } from "lucide-react";
import { Topbar } from "@/components/nav/Topbar";
import { FeedbackInbox } from "@/components/feedback/FeedbackInbox";

export default function SuperadminFeedbackPage() {
  return (
    <div>
      <Topbar title="Reports & feedback" subtitle="Content defects and technical problems reported across every environment" />
      <div className="container mx-auto max-w-[1000px] px-6 py-6 space-y-4">
        <Link href="/superadmin" className="inline-flex items-center gap-1 text-xs text-slate-400 transition hover:text-cyber-300">
          <ChevronLeft className="h-3.5 w-3.5" /> Back to Main environment
        </Link>
        <FeedbackInbox />
      </div>
    </div>
  );
}
