// Every log that reaches the screen — dashboard noise + stories (after enrichment and the
// SIEM mirror) and team-mode timelines (feed + inject support logs) — is the product its
// row says it is: the label maps to the module that renders the record, and the record
// carries no other product's identifying fields (no FortiGate record under "Palo Alto").
import { describe, it, expect } from "vitest";
import { storiesForCompany, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { enrichEvent } from "@/app/(app)/dashboard/liveEventEnrich";
import { siemMirror } from "@/app/(app)/dashboard/useLiveEvents";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import { applyStack, fitsStack, storyFitsStack, storyHonoursLocks, nativeView, authoredOf } from "./index";
import { categoryOf, coherentStack, COMPANY_STACKS, PRODUCT_LABEL, type Stack } from "./stack";
import type { TelemetryEvent } from "@/lib/sim/types";

// Identifying tokens of each product, by category: a record of product X must contain
// none of the tokens of another product Y of the same category.
const TOKENS: Record<string, Record<string, RegExp>> = {
  firewall: {
    paloalto: /PA-\d{3,4}|,TRAFFIC,|,THREAT,|"panos|PAN-OS/,
    fortigate: /"devname"|"vd":|FGT-|FG\d{3}[A-Z]/,
    checkpoint: /CheckPoint \d|originsicname|"loguid"/,
    cisco_ftd: /%FTD-\d|FTD-HQ|"AccessControlRuleAction"/,
    cisco_asa: /%ASA-\d|ASA-EDGE/,
  },
  edr: {
    crowdstrike: /"event_simpleName"|"composite_id"|"ConfigStateHash"|"aid":/,
    mde: /AdvancedHunting-|"DeviceId":|"InitiatingProcess/,
    sentinelone: /"agentRealtimeInfo"|"threatInfo"|"src\.process\.storyline|"agentUuid"/,
    sophos: /"sophos_pid"|"endpoint_id"|"meta_hostname"|"query_name"/,
  },
  idp: {
    okta: /"alternateId"|"debugContext"|"eventType":"user\./,
    entra: /"userPrincipalName"|"appDisplayName"|"conditionalAccessStatus"/,
  },
  vpn: {
    globalprotect: /GLOBALPROTECT|PA-\d{3,4}/,
    anyconnect: /%ASA-\d|asa-vpn/,
    fortigate_sslvpn: /"devname"|"tunneltype"/,
    zscaler_zpa: /"ConnectionID"|"ZEN"|"Connector"/,
    cloudflare_access: /"ray_id"|"RayID"|"app_domain"/,
  },
  email_security: {
    proofpoint: /"GUID"|"QID"|"threatsInfoMap"|"cluster"/,
    defender_o365: /"NetworkMessageId"|"EmailDirection"|AdvancedHunting-Email/,
  },
  dns: {
    infoblox: /named\[|"qname"|"rcode"/,
    windows_dns: /"PacketData"|"InternalPacketIdentifier"|Microsoft-Windows-DNS/,
  },
};
// Legacy view (no native module): raw-field namespaces that identify a product.
const RAW_NS: [RegExp, string, string][] = [
  [/^crowdstrike\./, "edr", "crowdstrike"], [/^s1\./, "edr", "sentinelone"], [/^sophos\./, "edr", "sophos"], [/^mde\./, "edr", "mde"],
  [/^data\.(devname|logid|vd)$|^fortigate\./, "firewall", "fortigate"], [/^(panos|pan)\./, "firewall", "paloalto"],
  [/^checkpoint\./, "firewall", "checkpoint"], [/^cisco\.(ftd|asa)\./, "firewall", "cisco"],
  [/^okta\./, "idp", "okta"], [/^azure\.signinlogs\./, "idp", "entra"],
];
const LABEL_TO_ID = new Map(Object.entries(PRODUCT_LABEL).map(([id, l]) => [l, id]));

const RUNS: [string, TelemetryEvent[], Stack][] = [
  ["nexacorp", BENIGN_EVENTS, {}],
  ["nexacorp", BENIGN_EVENTS, { edr: "crowdstrike", firewall: "fortigate", vpn: "anyconnect", idp: "okta", collab: "google_workspace", dns: "infoblox" }],
  ["nexacorp", BENIGN_EVENTS, { edr: "sophos", firewall: "cisco_asa", vpn: "fortigate_sslvpn", email_security: "proofpoint" }],
  ["medcore", COMPANY_EVENTS.medcore, {}],
  ["medcore", COMPANY_EVENTS.medcore, { edr: "mde", firewall: "paloalto", vpn: "globalprotect" }],
  ["rocketstack", COMPANY_EVENTS.rocketstack, {}],
  ["rocketstack", COMPANY_EVENTS.rocketstack, { edr: "sentinelone", firewall: "cisco_ftd", idp: "entra", collab: "m365" }],
  ["globallogis", COMPANY_EVENTS.globallogis, {}],
  ["globallogis", COMPANY_EVENTS.globallogis, { edr: "crowdstrike", firewall: "checkpoint", vpn: "zscaler_zpa" }],
  ["quantumbank", COMPANY_EVENTS.quantumbank, {}],
  ["quantumbank", COMPANY_EVENTS.quantumbank, { edr: "sophos", firewall: "fortigate", vpn: "cloudflare_access", dns: "infoblox" }],
];

function check(ev: TelemetryEvent, company: string, stack: Stack, where: string, problems: Set<string>) {
  const base = authoredOf(ev);
  const cat = categoryOf(base);
  const v = nativeView(ev, company, stack);
  const tag = `${company} ${JSON.stringify(stack)} ${where} ${base.id}`;
  if (v) {
    const shownId = LABEL_TO_ID.get(ev.vendor ?? "");
    const vcat = categoryOf({ ...base, source: base.source }) ?? cat;
    if (vcat && TOKENS[vcat] && shownId && shownId !== v.log.sourceId) problems.add(`${tag}: label "${ev.vendor}" but record is ${v.log.sourceId}`);
    if (cat && TOKENS[cat] && !shownId && ev.source !== "siem") {
      const eff = coherentStack({ ...(COMPANY_STACKS[company] ?? {}), ...stack });
      const want = eff[cat as keyof Stack];
      if (want && want !== v.log.sourceId) problems.add(`${tag}: label "${ev.vendor}" (company product ${want}) but record is ${v.log.sourceId}`);
    }
    const text = JSON.stringify(v.log.record) + (v.log.rawLine ?? "");
    const fam = cat ? TOKENS[cat] : undefined;
    if (fam) for (const [other, re] of Object.entries(fam)) {
      if (other === v.log.sourceId) continue;
      const m = text.match(re);
      if (m) problems.add(`${tag}: ${v.log.sourceId} record contains ${other} token "${m[0]}"`);
    }
  } else if (ev.source !== "siem") {
    const vend = (ev.vendor ?? "").toLowerCase();
    for (const k of Object.keys(ev.raw ?? {})) for (const [re, c, prod] of RAW_NS) {
      if (!re.test(k) || c !== cat) continue;
      const ok = prod === "crowdstrike" ? /crowd|falcon/.test(vend) : prod === "sentinelone" ? /sentinel/.test(vend) : prod === "sophos" ? /sophos/.test(vend)
        : prod === "mde" ? /defender|microsoft/.test(vend) : prod === "fortigate" ? /forti/.test(vend) : prod === "paloalto" ? /palo|pan-os/.test(vend)
        : prod === "checkpoint" ? /check ?point/.test(vend) : prod === "cisco" ? /cisco|firepower|asa/.test(vend) : prod === "okta" ? /okta/.test(vend) : /entra|azure|microsoft/.test(vend);
      if (!ok) problems.add(`${tag}: legacy row "${ev.vendor}" carries ${prod} field ${k}`);
    }
  }
}

describe("vendor consistency of every rendered log", () => {
  for (const [company, pool, stack] of RUNS) {
    it(`dashboard ${company} ${JSON.stringify(stack)}`, () => {
      const problems = new Set<string>();
      const chosen = Object.keys(stack).length > 0;
      let n = 0;
      for (const e0 of pool) {
        if (!fitsStack(e0, company, stack)) continue;
        const e = enrichEvent(applyStack(e0, company, stack), n++);
        check(e, company, stack, "feed", problems);
      }
      // As the dashboard and the team builder do: the chosen EDR, else the company's own.
      const edr = (stack.edr && PRODUCT_LABEL[stack.edr]) || COMPANY_PROFILES.find(c => c.id === company)?.architecture.edr;
      for (const diff of ["easy", "medium", "hard"] as const) for (const s of storiesForCompany(company, diff)) {
        const evs = instantiateStory(s, pool, edr, company).events ?? [];
        if (!(chosen ? storyFitsStack(evs, company, stack) : storyHonoursLocks(evs, company))) continue;
        for (const e0 of evs) {
          const e = enrichEvent(applyStack(e0, company, stack), n++);
          check(e, company, stack, `story:${s.id}`, problems);
          const m = siemMirror(e, n++);
          if (m) check(m, company, stack, `story:${s.id}:siem`, problems);
        }
      }
      expect([...problems].slice(0, 25)).toEqual([]);
    });
    it(`team ${company} ${JSON.stringify(stack)}`, () => {
      const problems = new Set<string>();
      const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
      for (const diff of ["easy", "medium", "hard"] as const) for (const seed of ["a", "b"]) {
        const tl = buildTeamTimeline(company, diff, `${seed}-${company}`, null, teamLoad(diff, roster), stack);
        for (const t of tl) {
          if (t.channel !== "feed") continue;
          const ev = t.body as unknown as TelemetryEvent;
          check(enrichEvent(ev, 0), company, stack, `team:${diff}`, problems);
        }
      }
      expect([...problems].slice(0, 25)).toEqual([]);
    });
  }
});
