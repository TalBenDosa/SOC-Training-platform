// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from "vitest";
import { clearDashboardLearnerStore, parseStoredReport, setDashboardOwner } from "./learnerStorage";

describe("Dashboard learner storage on a shared device", () => {
  beforeEach(() => localStorage.clear());

  it("a different learner on the browser does not see the previous one's report, drafts or searches", () => {
    setDashboardOwner("student-a");
    localStorage.setItem("soc_last_training_report_v1", "{}");
    localStorage.setItem("soc_report_draft_nexacorp_inc1", "{}");
    localStorage.setItem("soc:saved-searches", "[]");
    localStorage.setItem("soc_welcome_seen_v1", "1");            // not learner data: kept
    setDashboardOwner("student-a");                               // same learner: kept
    expect(localStorage.getItem("soc_last_training_report_v1")).toBe("{}");
    setDashboardOwner("student-b");
    expect(localStorage.getItem("soc_last_training_report_v1")).toBeNull();
    expect(localStorage.getItem("soc_report_draft_nexacorp_inc1")).toBeNull();
    expect(localStorage.getItem("soc:saved-searches")).toBeNull();
    expect(localStorage.getItem("soc_welcome_seen_v1")).toBe("1");
  });

  it("sign-out clears it", () => {
    localStorage.setItem("soc_selected_company_v1", "medcore");
    clearDashboardLearnerStore();
    expect(localStorage.getItem("soc_selected_company_v1")).toBeNull();
  });

  it("a corrupt or old stored report is ignored instead of crashing the page", () => {
    expect(parseStoredReport(null)).toBeNull();
    expect(parseStoredReport("{not json")).toBeNull();
    expect(parseStoredReport(JSON.stringify({ band: "good" }))).toBeNull();
    expect(parseStoredReport(JSON.stringify({ facts: {}, band: "good", metrics: [], strengths: [], improvements: [] }))).not.toBeNull();
  });
});
