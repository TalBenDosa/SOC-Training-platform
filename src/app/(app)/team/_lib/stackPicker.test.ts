// QA L3: Google Workspace forces Proofpoint (Defender for Office 365 needs Exchange
// Online); switching back to Microsoft 365 used to leave that forced Proofpoint behind.
import { describe, it, expect } from "vitest";
import { nextStack, stackDelta } from "@/components/training/StackPicker";
import { COMPANY_STACKS, coherentStack, type Stack } from "@/lib/logs/native/stack";

const merged = (company: string, delta: Stack) => coherentStack({ ...(COMPANY_STACKS[company] ?? {}), ...delta });

describe("nextStack (Session Builder product picker)", () => {
  it("Google → back to M365 returns the mail filter to the company default when Google forced it", () => {
    const a = nextStack("nexacorp", merged("nexacorp", {}), "collab", "google_workspace", false);
    expect(a.stack).toEqual({ collab: "google_workspace", email_security: "proofpoint" });
    expect(a.forcedMail).toBe(true);
    const b = nextStack("nexacorp", merged("nexacorp", a.stack), "collab", "m365", a.forcedMail);
    expect(b.stack).toEqual({});                       // Defender for Office 365 again — the company's own
    expect(b.forcedMail).toBe(false);
  });

  it("a Proofpoint the trainer picked themselves survives the round trip", () => {
    const a = nextStack("nexacorp", merged("nexacorp", {}), "email_security", "proofpoint", false);
    const b = nextStack("nexacorp", merged("nexacorp", a.stack), "collab", "google_workspace", a.forcedMail);
    expect(b.forcedMail).toBe(false);                  // nothing was forced: Proofpoint was already chosen
    const c = nextStack("nexacorp", merged("nexacorp", b.stack), "collab", "m365", b.forcedMail);
    expect(c.stack).toEqual({ email_security: "proofpoint" });
  });

  it("picking the mail filter by hand clears the forced flag", () => {
    const a = nextStack("nexacorp", merged("nexacorp", {}), "collab", "google_workspace", false);
    const b = nextStack("nexacorp", merged("nexacorp", a.stack), "email_security", "proofpoint", a.forcedMail);
    expect(b.forcedMail).toBe(false);
    const c = nextStack("nexacorp", merged("nexacorp", b.stack), "collab", "m365", b.forcedMail);
    expect(c.stack).toEqual({ email_security: "proofpoint" });
  });

  it("stackDelta keeps only the categories that differ from the company", () => {
    expect(stackDelta("nexacorp", { ...COMPANY_STACKS.nexacorp, edr: "crowdstrike" })).toEqual({ edr: "crowdstrike" });
  });
});
