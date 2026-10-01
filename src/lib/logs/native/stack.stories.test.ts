// Every story and feed record a chosen stack can show, across companies and
// difficulties: labelled for the chosen products, rendered by them, schema-clean,
// no other vendor of the same category named in the row text, no product the session
// swapped out named on any row, no vendor-specific story under another vendor, and no
// Microsoft 365 client noise on a Google Workspace shop's endpoints.
import { describe, it, expect } from "vitest";
import { storiesForCompany, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { applyStack, fitsStack, storyFitsStack, storyHonoursLocks, nativeView, NATIVE_SOURCES, authoredOf } from "./index";
import { categoryOf, coherentStack, PRODUCT_LABEL, COMPANY_STACKS, type Stack } from "./stack";
import { validateNative } from "./validate";
import type { TelemetryEvent } from "@/lib/sim/types";

// Other products' names per category (the Windows built-in AV is legitimately named under any EDR).
const NAMES: Record<string, Record<string, RegExp>> = {
  edr: {
    crowdstrike: /CrowdStrike|Falcon/, sentinelone: /SentinelOne/, sophos: /Sophos/,
    mde: /Defender for Endpoint|Microsoft Defender(?! Antivirus| for Office)|Defender ATP/,
  },
  firewall: {
    paloalto: /Palo Alto|PAN-OS/, fortigate: /FortiGate|Fortinet/, checkpoint: /Check Point/,
    cisco_ftd: /Firepower/, cisco_asa: /Cisco ASA/,
  },
  idp: { entra: /Entra ID|Azure AD|Azure Active Directory|Conditional Access/, okta: /Okta/ },
  email_security: { defender_o365: /Defender for Office 365/, proofpoint: /Proofpoint/ },
  collab: { m365: /Microsoft 365|Office 365|Microsoft Office|SharePoint|OneDrive|Exchange Online|Outlook/, google_workspace: /Google Workspace|Google Drive|Gmail/ },
};
const SELECTABLE = new Set(["edr", "firewall", "vpn", "idp", "collab", "email_security", "dns"]);
const BADGE: Record<string, string> = { google_workspace: "gws", okta: "okta", proofpoint: "email_gateway" };

const STACKS: [string, Stack][] = [
  ["nexacorp", { edr: "crowdstrike", firewall: "fortigate", vpn: "anyconnect", idp: "okta", collab: "google_workspace", email_security: "proofpoint", dns: "infoblox" }],
  ["nexacorp", { edr: "sentinelone", firewall: "checkpoint", collab: "google_workspace" }],
  ["medcore", { edr: "sophos", firewall: "cisco_asa", vpn: "zscaler_zpa" }],
  ["rocketstack", { edr: "mde", firewall: "paloalto", idp: "entra", collab: "m365", email_security: "defender_o365" }],
  ["globallogis", { edr: "crowdstrike", firewall: "cisco_ftd", vpn: "cloudflare_access", idp: "okta" }],
  ["quantumbank", { edr: "sentinelone", firewall: "fortigate", email_security: "proofpoint", dns: "windows_dns" }],
  // The companies' own products (no choice made) — the lock and fit rules apply there too.
  ["nexacorp", {}], ["rocketstack", {}], ["medcore", {}], ["globallogis", {}], ["quantumbank", {}],
];

function audit(ev: TelemetryEvent, company: string, stack: Stack, problems: string[], strict = true) {
  const eff = coherentStack({ ...(COMPANY_STACKS[company] ?? {}), ...stack });
  const own = COMPANY_STACKS[company] ?? {};
  const base = authoredOf(ev);
  const cat = categoryOf(base);
  const desc = ev.description ?? "";
  for (const [c, sid] of Object.entries(eff)) {
    if (!sid || c === cat || sid === own[c as keyof Stack] || !NAMES[c]) continue;
    for (const [other, re] of Object.entries(NAMES[c])) {
      if (other !== sid && re.test(desc)) problems.push(`${company} ${base.id} [${cat ?? base.source}, swapped ${c}→${sid}] names ${other}: ${desc.slice(0, 100)}`);
    }
  }
  if (eff.collab === "google_workspace" && cat && ["edr", "host_telemetry", "onprem_ad", "dns", "firewall", "proxy"].includes(cat)
    && /\b(Outlook|Teams|OneDrive|SharePoint)\b|OUTLOOK\.EXE|office365\.com/.test(desc)) problems.push(`${company} ${base.id} M365 client noise in a Google shop: ${desc.slice(0, 100)}`);
  if (eff.firewall !== "fortigate" && /FortiOS/.test(desc)) problems.push(`${company} ${base.id} FortiOS story under ${eff.firewall}: ${desc.slice(0, 100)}`);
  const chosen = cat && SELECTABLE.has(cat) ? eff[cat as keyof Stack] : undefined;
  if (!chosen) return;
  const tag = `${company} ${base.id ?? "?"} [${cat}→${chosen}]`;
  if (ev.vendor !== PRODUCT_LABEL[chosen]) problems.push(`${tag} vendor "${ev.vendor}"`);
  if (BADGE[chosen] && ev.source !== BADGE[chosen]) problems.push(`${tag} badge "${ev.source}"`);
  for (const [other, re] of Object.entries(NAMES[cat!] ?? {})) {
    if (other !== chosen && ev.description && re.test(ev.description)) problems.push(`${tag} names ${other}: ${ev.description.slice(0, 100)}`);
  }
  const v = nativeView(ev, company, stack);
  if (!v) { if (strict) problems.push(`${tag} no native render`); return; }
  if (v.log.sourceId !== chosen) problems.push(`${tag} rendered by ${v.log.sourceId}`);
  const viol = validateNative(v.log, NATIVE_SOURCES[v.log.sourceId]!.schema);
  if (viol.length) problems.push(`${tag} ${viol.slice(0, 2).map(x => `${x.problem}:${x.path}`).join(", ")}`);
}

describe("chosen stacks — every eligible story and feed record", () => {
  for (const [company, stack] of STACKS) {
    it(`${company} ${JSON.stringify(stack)}`, () => {
      const problems: string[] = [];
      const edr = stack.edr ? PRODUCT_LABEL[stack.edr] : undefined;
      const pool = (COMPANY_EVENTS[company]?.length ? COMPANY_EVENTS[company] : BENIGN_EVENTS) as TelemetryEvent[];
      const counts: string[] = [];
      for (const diff of ["easy", "medium", "hard"] as const) {
        const all = storiesForCompany(company, diff);
        let ok = 0;
        for (const s of all) {
          const events = instantiateStory(s, pool, edr, company).events ?? [];
          if (!(Object.keys(stack).length ? storyFitsStack(events, company, stack) : storyHonoursLocks(events, company))) continue;
          ok++;
          for (const e of events) audit(applyStack(e, company, stack), company, stack, problems, Object.keys(stack).length > 0);
        }
        counts.push(`${diff} ${ok}/${all.length}`);
        expect(ok, `${company} ${diff}: no story fits`).toBeGreaterThan(0);
      }
      let feed = 0;
      for (const e of [...pool, ...BENIGN_EVENTS]) {
        if (!fitsStack(e, company, stack)) continue;
        feed++;
        audit(applyStack(e, company, stack), company, stack, problems, Object.keys(stack).length > 0);
      }
      console.log(`[stack-stories] ${company}: ${counts.join(", ")}; feed ${feed}; problems ${problems.length}`);
      expect([...new Set(problems)].slice(0, 25)).toEqual([]);
    });
  }
});
