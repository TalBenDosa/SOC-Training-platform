/**
 * R9 No answer leaks in what the learner reads before deciding.
 *  a. Verdict keys in a record: is_malicious, attack_stage, expected_verdict, ground_truth, is_attack,
 *     fp_explanation, correct_verdict, it_verify_result, is_baseline, kill_chain_stage; a boolean
 *     `malicious: true`; `maintenance_window` / `in_maintenance` set to true.
 *  b. Verdict words in an identity value (user, account, host, sender): attacker, hacker, evil,
 *     malicious, pwned, backdoor.
 *  c. The authored analyst description of an attack row (the conclusion) copied into the native
 *     record, as src/lib/logs/native/answerLeak.test.ts checks for the feed, here on every surface
 *     that renders native records.
 */
import type { Checker, Violation } from "../types";
import { leaves } from "../util";

const LEAK_KEY = /^(is_?malicious|attack_?stage|expected_?verdict|verdict_?expected|ground_?truth|is_?attack|is_?fp|fp_?explanation|correct_?verdict|it_?verify_?result|is_?baseline|kill_?chain_?stage|attack_?phase|is_?decoy)$/i;
const ID_KEY = /^(user|username|user_name|userprincipalname|upn|account|accountname|accountupn|targetusername|subjectusername|actor|alternateid|initiatedby|caller|hostname|host|computer|computername|devicename|workstation|workstationname|src_?user|dst_?user|suser|duser|email|sender|recipient|mailbox|owner|name)$/i;
const ID_PARENT = /(user|account|actor|host|device|computer|sender|recipient|initiat|identity|principal)/i;
const VERDICT_WORD = /(?:^|[^a-z])(attacker|hacker|evil|malicious|pwned|backdoor)(?:[^a-z]|$)/i;

export const r9: Checker = c => {
  const out: Violation[] = [];
  const seen = new Set<string>();
  const push = (v: Violation) => { const k = `${v.surface}|${v.rowId}|${v.detail}`; if (!seen.has(k)) { seen.add(k); out.push(v); } };
  for (const r of c.rows) {
    // XDR background rows have no stable id of their own: one key per table.
    const rowId = r.meta?.baseline ? `${r.company}:${r.source}:baseline` : r.rowId;
    if (typeof r.raw !== "string") {
      for (const [p, v] of leaves(r.raw)) {
        const parts = p.replace(/\[\]/g, "").split(".");
        const leaf = parts[parts.length - 1];
        if (LEAK_KEY.test(leaf) && v !== null && v !== "" && v !== undefined) push({ surface: r.surface, rule: "R9", rowId, detail: `verdict field ${leaf}`, company: r.company, example: `${p}=${String(v).slice(0, 40)}` });
        if (/^malicious$/i.test(leaf) && (v === true || v === "true")) push({ surface: r.surface, rule: "R9", rowId, detail: "malicious: true", company: r.company, example: p });
        if (/^(maintenance_?window|in_?maintenance|maintenance)$/i.test(leaf) && (v === true || v === "true" || v === "yes")) push({ surface: r.surface, rule: "R9", rowId, detail: "maintenance flag on the row", company: r.company, example: p });
        if (typeof v === "string" && ID_KEY.test(leaf) && (leaf.toLowerCase() !== "name" || ID_PARENT.test(parts.slice(0, -1).join("."))) && VERDICT_WORD.test(v)) {
          push({ surface: r.surface, rule: "R9", rowId, detail: `verdict word in ${leaf}`, company: r.company, example: `${p}=${v.slice(0, 60)}` });
        }
      }
    }
    const ev = r.ev;
    if (r.native && r.isAttack && ev?.description && ev.description.length >= 40 && ev.mitre_technique) {
      const needle = ev.description.slice(0, 40);
      if (needle.includes(" ") && (JSON.stringify(r.native.record) + (r.native.rawLine ?? "")).includes(needle)) {
        push({ surface: r.surface, rule: "R9", rowId, detail: "authored conclusion in the record", company: r.company, example: needle });
      }
    }
  }
  return out;
};
