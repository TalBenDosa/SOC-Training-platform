/**
 * SOC glossary — beginner-friendly definitions for terms shown across the
 * dashboard. Rendered via the <Term> tooltip component so a student meeting
 * a SOC for the first time never has to guess what an acronym means.
 */

export interface GlossaryEntry {
  term: string;       // display name
  def: string;        // 1-2 sentence plain-English definition
  example?: string;   // short concrete example
}

export const GLOSSARY: Record<string, GlossaryEntry> = {
  soc: {
    term: "SOC",
    def: "Security Operations Center — the team (and room) that watches an organization's systems around the clock, spots attacks, and responds to them.",
  },
  siem: {
    term: "SIEM",
    def: "Security Information and Event Management — the platform that collects logs from every security tool into one searchable feed. This dashboard simulates one.",
    example: "Splunk, Microsoft Sentinel and QRadar are popular SIEMs.",
  },
  alert: {
    term: "Alert",
    def: "A detection rule that fired on an event — a signal that needs a human to look. An alert is only a suspicion; a confirmed alert becomes an incident.",
  },
  incident: {
    term: "Incident",
    def: "A confirmed security event that is really happening and needs a response. In a real SOC you 'raise an incident' and escalate it — that's what the Report Incident button does here.",
  },
  disposition: {
    term: "Disposition",
    def: "The verdict you assign to an alert after triage: True Positive (real), Benign (real but harmless/expected), or False Positive (the rule was wrong).",
  },
  ioc: {
    term: "IOC",
    def: "Indicator of Compromise — a piece of evidence that points to an attack: a malicious IP address, file hash, domain, or compromised username.",
    example: "The attacker's IP 91.108.4.33 is an IOC you can block at the firewall.",
  },
  mitre: {
    term: "MITRE ATT&CK",
    def: "A public catalogue of real attacker techniques, each with an ID like T1566. SOC teams use it as a shared language to describe what an attacker did.",
    example: "T1566.001 = phishing with a malicious attachment.",
  },
  ttp: {
    term: "TTP",
    def: "Tactics, Techniques and Procedures — the behaviour patterns of an attacker: what they want (tactic), how they do it (technique), and their exact steps (procedure).",
  },
  edr: {
    term: "EDR",
    def: "Endpoint Detection and Response — an agent installed on every computer that records processes, files and network connections, and can isolate an infected machine.",
    example: "CrowdStrike Falcon and Microsoft Defender for Endpoint are EDRs.",
  },
  rule_level: {
    term: "Rule Level",
    def: "Severity score 1-10 assigned by the detection rule. 1-3 is routine noise, 4-6 deserves a look, 7-10 is a likely threat that needs action.",
  },
  tp: {
    term: "True Positive",
    def: "An alert that turned out to be a REAL attack. Marking a verdict as True Positive means: this is malicious, respond now.",
  },
  fp: {
    term: "False Positive",
    def: "An alert that looked suspicious but has an innocent explanation. Most SOC alerts are false positives — telling them apart is the analyst's core skill.",
    example: "40 failed logins can be an attack — or someone who forgot their password.",
  },
  triage: {
    term: "Triage",
    def: "The quick first assessment of an alert: is it real, how bad is it, and who should handle it — just like an ER nurse prioritising patients.",
  },
  escalation: {
    term: "Escalation",
    def: "Passing an incident to a more senior analyst (Tier 2/3) when it's confirmed serious or beyond your authority — with your findings attached.",
  },
  c2: {
    term: "C2",
    def: "Command & Control — the attacker's remote-control channel to malware inside the network. Infected machines 'beacon' out to the C2 server for instructions.",
  },
  sla: {
    term: "SLA",
    def: "Service Level Agreement — the maximum time the SOC promises to react to an alert. The countdown timer shows your remaining response window.",
  },
  benign: {
    term: "Benign",
    def: "Normal, harmless activity. Most of what a SOC sees is benign — employees logging in, updates installing, emails arriving.",
  },
  kill_chain: {
    term: "Kill Chain",
    def: "The sequence of stages an attack moves through — from initial access, to execution, to stealing data. Understanding the chain tells you what the attacker will do next.",
  },
};
