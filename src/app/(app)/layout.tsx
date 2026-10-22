import { redirect } from "next/navigation";
import { Sidebar } from "@/components/nav/Sidebar";
import { MotionProvider } from "@/components/MotionProvider";
import { EarnMoment } from "@/components/EarnMoment";
import { SyncStatus } from "@/components/system/SyncStatus";
import { OrgContentNotice } from "@/components/system/OrgContentNotice";
import { AccessDeniedNotice } from "@/components/system/AccessDeniedNotice";
import { ReportProblem } from "@/components/feedback/ReportProblem";
import { PlanAnnouncementModal } from "@/components/plans/PlanAnnouncementModal";
import { affiliationExpired } from "@/lib/org/affiliationGate";
import { AppBrandScope } from "@/lib/brand/BrandContext";
import { getAppBrand } from "@/lib/brand/appBrand";
import { featuresForOrg } from "@/lib/brand/server";
import { themeCss } from "@/lib/brand/theme";
import { getValidatedAuth } from "@/lib/auth/validatedUser";
import { decodeOrgClaim } from "@/lib/auth/orgClaim";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  // The 100-day rule (0028): an org student whose affiliation lapsed is
  // diverted to /renew before ANY app page renders. Server-side, so it cannot
  // be skipped by disabling JS; /renew itself lives in the (auth) group,
  // outside this layout, so the diversion cannot loop.
  if (await affiliationExpired()) {
    redirect("/renew");
  }
  // The environment's brand and plan, resolved HERE on the server so the first paint already
  // shows the right logo, colours and nav (no platform-logo flash before a white-label
  // environment's own, including right after an environment switch).
  const { brand, env } = await getAppBrand();
  const auth = await getValidatedAuth();
  const orgId = auth ? decodeOrgClaim(auth.session?.access_token).orgId : null;
  const features = orgId ? await featuresForOrg(orgId) : null;
  return (
    // Inside the app the brand follows the current environment; public pages never do.
    <AppBrandScope initialEnvBrand={env} initialFeatures={features}>
    {/* The logo is fetched first, before anything else on the page. */}
    {brand.whiteLabel && brand.logoSrc && <link rel="preload" as="image" href={brand.logoSrc} fetchPriority="high" />}
    {/* A white-label environment's colours on a platform host, rendered with the page (the
        white-label domain's own are already in the root layout). Unmounts with the app. */}
    {env?.theme && <style>{themeCss(env.theme)}</style>}
    <MotionProvider>
      <div className="flex min-h-screen">
        <Sidebar />
        <main id="main-content" className="flex-1 min-w-0">{children}</main>
      </div>
      <EarnMoment />
      {/* Clear notice when the middleware bounced the user off a staff-only area
          (?reason=forbidden) — replaces the old silent redirect to the landing page. */}
      <AccessDeniedNotice />
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
    </AppBrandScope>
  );
}
