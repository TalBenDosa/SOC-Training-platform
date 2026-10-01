import { redirect } from "next/navigation";
import { Sidebar } from "@/components/nav/Sidebar";
import { MotionProvider } from "@/components/MotionProvider";
import { EarnMoment } from "@/components/EarnMoment";
import { SyncStatus } from "@/components/system/SyncStatus";
import { OrgContentNotice } from "@/components/system/OrgContentNotice";
import { ReportProblem } from "@/components/feedback/ReportProblem";
import { PlanAnnouncementModal } from "@/components/plans/PlanAnnouncementModal";
import { affiliationExpired } from "@/lib/org/affiliationGate";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  // The 100-day rule (0028): an org student whose affiliation lapsed is
  // diverted to /renew before ANY app page renders. Server-side, so it cannot
  // be skipped by disabling JS; /renew itself lives in the (auth) group,
  // outside this layout, so the diversion cannot loop.
  if (await affiliationExpired()) {
    redirect("/renew");
  }
  return (
    <MotionProvider>
      <div className="flex min-h-screen">
        <Sidebar />
        <main id="main-content" className="flex-1 min-w-0">{children}</main>
      </div>
      <EarnMoment />
      {/* Silent unless a write actually failed — see syncState.ts */}
      <SyncStatus />
      <OrgContentNotice />
      {/* Global technical-bug reporter — floats on every app page */}
      <ReportProblem />
      {/* New / updated learning plan → one popup (learners are never emailed
          about plans). Shares the bell's notifications store; renders nothing
          for guests, users without an org, or when nothing is unread. */}
      <PlanAnnouncementModal />
    </MotionProvider>
  );
}
