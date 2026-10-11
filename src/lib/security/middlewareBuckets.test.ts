import { describe, it, expect, vi } from "vitest";

// middleware.ts pulls in the Supabase/Upstash clients at import time; the
// classification under test is pure, so stub the I/O modules.
vi.mock("@/lib/security/rateLimit", () => ({ checkRateLimit: vi.fn() }));
vi.mock("@/lib/supabase/middleware", () => ({ refreshSupabaseSession: vi.fn() }));

const { isExpensive } = await import("@/middleware");

describe("isExpensive — which API calls share the tight (10/min) bucket", () => {
  it("paid generation and grading stay expensive", () => {
    expect(isExpensive("/api/lessons/generate", "POST")).toBe(true);
    expect(isExpensive("/api/lessons/generate-stream", "POST")).toBe(true);
    expect(isExpensive("/api/quizzes/generate", "POST")).toBe(true);
    expect(isExpensive("/api/scenarios/phishing-malware-basic/grade", "POST")).toBe(true);
    expect(isExpensive("/api/dashboard/incident-report", "POST")).toBe(true);
    expect(isExpensive("/api/org/media", "POST")).toBe(true);
    expect(isExpensive("/api/org/media/sign", "POST")).toBe(true);
  });

  it("everyday student reads are NOT expensive (a class behind one NAT must not 429)", () => {
    expect(isExpensive("/api/lessons/soc-foundations--what-is-a-soc", "GET")).toBe(false);
    expect(isExpensive("/api/lessons/soc-foundations--what-is-a-soc/quiz/grade", "POST")).toBe(false);
    expect(isExpensive("/api/lessons/soc-foundations--what-is-a-soc/complete", "POST")).toBe(false);
    expect(isExpensive("/api/org/media/3f1c0e7a-1111-4222-8333-444455556666/url", "GET")).toBe(false);
    expect(isExpensive("/api/org/media", "GET")).toBe(false);
  });
});
