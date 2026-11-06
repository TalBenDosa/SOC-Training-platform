import type { HuntStep, HuntTable } from "./hunt";
/**
 * Operation Mode — a presentation layer OVER an existing Learning Room.
 *
 * A RoomExperience never carries content or answers: it only groups the room's
 * existing task ids into stations, names them, and adds narrative chrome
 * (codename, handler lines, personas). Grading, XP and the 65% mastery gate
 * stay exactly where they are (RoomClient + /api/rooms/.../submit), so a room
 * plays identically in Classic and Operation mode as far as scoring goes.
 *
 * Concept doc: docs/CONCEPT-gamified-learning-rooms.md
 */

export type ThemeId = "mailroom" | "ransomware" | "domain" | "c2" | "hospital" | "city" | "datacenter" | "soc" | "perimeter" | "endpoint" | "linux" | "pipeline" | "crypto" | "time" | "forensics" | "identity" | "malware" | "risk" | "patching" | "killchain" | "netsec" | "edr" | "mind" | "sensors" | "webapp" | "lures" | "macos" | "evtx" | "varlog" | "siem" | "ingest" | "email" | "protocols" | "dlp" | "persistence" | "powershell" | "privesc" | "attack" | "ad" | "wazuh" | "sentinel" | "detection" | "m365" | "falcon" | "s1" | "detonation" | "nightqueue" | "forensics2" | "vpn" | "fwlogs" | "dns" | "ngfw" | "avedr" | "llm" | "wire" | "webops" | "baremetal" | "smuggle" | "tenant" | "replyall" | "sharedlink" | "lastword" | "breadcrumb" | "tabletop" | "loosethread" | "whogoes" | "papertrail" | "badnews" | "frontdoor" | "autopilot" | "crownjewels" | "shareddrive" | "modelbehaviour" | "helpinghand" | "longgame" | "firstrule" | "deepquery" | "exitroute" | "sealedroom" | "sidedoor" | "returnpath" | "threeheads" | "pagefile" | "processtree" | "coldvault" | "diamond";

/**
 * The room's 3D world on its main screen. Decorative (never clickable): it shows
 * progress, the board around it carries the controls.
 *  - shield:  holographic shield on a projector platform (cards layout)
 *  - gates:   one armoured gate per station on a ring around a holo globe
 *  - tower:   a tower climbed floor by floor, one floor per station
 *  - network: relay nodes joined by beams, packets travel the cleared route
 *  - campus:  a hospital campus at night; each cleared station powers a building
 *             back up, and the sky turns from night to dawn as the room is cleared
 *  - city:    a city seen through a "lens"; each cleared station switches on one
 *             more invisible layer (connections, locks, attackers, attacks, alerts)
 *  - datapath: network hardware on one cable run in a data hall (laptop, switch,
 *             router, NAT firewall, internet, server) with a hologram OSI stack;
 *             each cleared station brings the next device online
 *  - socfloor: a SOC operations room: video wall, desks by tier, tool towers;
 *             stations switch on the wall, the tiers, the tools, then the alert
 *  - portwall: a perimeter firewall face of port sockets with protocol traffic
 *             streaming in; stations light port groups, then abuse and detection
 *  - hostcore: inside one Windows host: kernel core and rings, folder tree,
 *             registry hive, process tree, PowerShell console, a caged macro chain
 *  - fstree:  a Linux server's directory tree grown from "/": branches, permission
 *             triplets, cron clock and intruder SSH key, then an audit beam
 *  - logriver: a log pipeline: sources, syslog collector, normalisation prism,
 *             storage tiers, an immutable lock, a "log cleared" card bouncing off
 *  - cipherlab: an encoder cube, a cipher vault and a hash press on a bench, a
 *             fingerprint wall, and a TLS tunnel with its SNI readable outside
 *  - chrono:  three world clocks, an NTP server syncing source towers, and a
 *             timeline track whose event beads slide into their true order
 *  - dissect: a raw log line on a table, five field lenses dropping onto it,
 *             format monoliths, a normalisation funnel and a "not logged" gap
 *  - idgate:  an authentication ring before authorization doors, three factor
 *             pillars, token coins (one stolen, then shattered by a revoke beam),
 *             an MFA push storm, account-type towers and a logon stream
 *  - specimen: a malware quarantine floor: MOVES/WANTS axes with capsules, a
 *             blocked stage-2 packet, a C2 heartbeat, a stealer funnel, a file
 *             wall locking and shattering, and a rootkit under a glass OS floor
 *  - riskcore: threat/weakness/impact beams feeding a core, a CVSS gauge and KEV
 *             beacon, an attack-surface dome with one vector lance, a triage board
 *  - patchline: a conveyor of findings through a CVE/CWE/CVSS press, a vector
 *             rack, an EPSS tube and KEV siren, a glass server probed outside and
 *             in, and patch/compensate/accept bins under a verify ring
 *  - chainlinks: seven interlocked kill chain links with an attack orb, shields,
 *             a C2 link that shatters, and a turning Diamond Model above
 *  - zonewall: internet, outer firewall, DMZ with WAF and an IDS on a copy line,
 *             inner firewall, VLAN islands behind glass, and a SYN-scanning probe
 *  - blackbox: a laptop ringed by AV/NGAV/EDR/XDR rings, telemetry rising to a
 *             recorder, an isolation dome, and a process-tree hologram
 *  - mindlab: a prism splitting an alert into two hypotheses, six question
 *             satellites, a baseline ribbon with a spike, bias fog, fact/assumption pillars
 *  - sightlines: a cut-away stack: agent halos over an agentless hypervisor, an
 *             inline gate and a tap, a WAF, mail gate, scanner, cloud and SIEM well
 *  - webpath: a request travelling browser > TLS > WAF > web > app > database,
 *             its parts, a tampered packet, attack markers per tier, a rogue tab
 *  - baitshop: six lures on hooks around a workstation: padlocked macro, fake
 *             CAPTCHA, swapped wallet strings, poisoned results, disc, mining tab
 *  - orchard: macOS laid out: XNU core, DMG/PKG doors, a Gatekeeper arch with
 *             seals, a fake dialog and leaking Keychain, TCC toggles, a launchd tree
 *  - evtxtape: a recorder spooling event-ID tape that wraps, a logon-type dial,
 *             a w3wp.exe pillar growing cmd.exe, and a password-spray fan
 *  - varlog:  a /var/log cabinet, a journal crystal with query beams, an SSH door
 *             with knocks and a planted key, and a cron clock beside a gapped ribbon
 *  - radar:   a SIEM control tower: a radar table fed by source towers,
 *             correlation threads, an alert chute into TP/BTP/FP bins, a query beam
 *  - intake:  sources piping logs over UDP/TCP/TLS to a collector, one silent,
 *             a parser gear splitting blobs into fields, a schema funnel, a SIEM vault
 *  - postmark: an envelope hopping relay towers, SPF/DKIM/DMARC seals at a gate
 *             with a DNS signpost, a hijacked thread, and a wire stopped by a shield
 *  - protostack: a seven-layer glass stack, a TCP handshake and a UDP dart, a DNS
 *             tree and TLS tunnel, an ARP spoof, and a beacon in an allowed pipe
 *  - sealedbrief: a document vault with endpoint/network/cloud watch-posts, a
 *             scanner and confidence bar, an action gate, a trace and a verdict seal
 *  - sparekey: a host core with Run-key branches, a cron clock, a gear over a hidden
 *             WMI layer, a 4698 card, and a cloud ring of keys closed by a lock
 *  - objectpipe: two consoles at the ends of a pipe, object cubes flowing through
 *             filter, select and sort rings into a CSV, a PID beam, and a task to hunt
 *  - integrityladder: four glowing decks (Low to System) a process climbs, an LSASS
 *             vault, a rewritten handler key, an impersonation mask and a service path
 *  - matrixwall: a wall of fifteen tactic columns whose technique tiles light, an
 *             ID decoder, a coverage layer with dark gaps, and a report scroll
 *  - domaintree: a forest of domain trees around a DC keystone, a Kerberos ticket
 *             loop, roasting embers, a crown vault, and a poisoned relay link
 *  - wazuhflow: agents streaming packets into a manager core, a decoder gear and a
 *             rule sieve, a watched file vault, and an alert beacon
 *  - skyquery: a cloud workspace sphere fed by connector streams, table pillars,
 *             a KQL beam that narrows, an incident hexagon and a raw-row card
 *  - noisefilter: a river of event particles through logic gates, a Sigma scroll,
 *             tuning baffles that thin the noise, a judge lens and one true signal
 *  - tenantcloud: a tenant cloud ring over Exchange and SharePoint racks, a mail
 *             shield gate, an audit terminal, a forwarding leak and a closing padlock
 *  - talon: a fleet of sensor laptops under a cloud threat graph, a policy gate,
 *             an RTR terminal beam to one far laptop, a process tree and a contain ring
 *  - storyline: purple event beads strung on one Storyline thread over a brewery's
 *             racks, a Threat Center panel, a remote shell and a rewinding rollback dial
 *  - detonation: a glass sandbox cage where a sample bursts into behaviour arrows,
 *             a static bench, a YARA terminal scanning quarantine files, and a shield
 *  - nightqueue: a conveyor of alert cards into an analyst desk and four verdict
 *             chutes, a priority matrix of glowing cells, and a handover shield
 *  - coldcase: a sealed evidence bag on a light table, a RAM module and a disk
 *             platter under a write blocker, a timeline rail of artefacts, and a seal
 *  - longdistance: laptops on a ring of far-off nodes tunnelling into a VPN gateway,
 *             a line-up of attacker silhouettes, an inside trail and a verdict shield
 *  - denyall: three firewall appliances guarding zone walls, a ticking beacon dial,
 *             a stack of rule slabs a packet falls through, and a deny gate
 *  - lookup: a resolver tower answering library PCs, glowing name cards (one a
 *             lookalike), trick cards orbiting, a metrics gauge and a sinkhole
 *  - generations: a corridor of four firewall generations (grate, stateful rack,
 *             NGFW rack, TLS padlock) packets pass through, zone rings and a beacon
 *  - secondopinion: a scanner arch a fileless ghost slips past, a laptop in kernel
 *             rings, three EDR consoles and a process tree with one red node
 *  - ignoreall: a glowing model core fed by a stream of text, a gateway ring with
 *             a filter, document chunks, a poisoned stack and a copied shadow core
 *  - wirelevel: two racks on a wire with TCP flag switches, a probe along the rack
 *             row, TTL rings counting down, a capture screen and a burst of resets
 *  - opensesame: requests at a WAF gate, an IIS rack and its log, a second record
 *             joined by a beam, a scanner node and a stray file spawning a console
 *  - baremetal: the stack in section, vCenter over glass guests over hosts and a datastore;
 *             a grant cascades down, a host's door opens, guests go dark and disks unlock
 *  - specialdelivery: text passes a scanner arch and locks into a file over a laptop;
 *             four signed pillars, a red rider on one, a command-line panel and a rule shield
 *  - tenantzero: a tenant core with objects in orbit, three condition rings, a role
 *             lamp on a timer and a globe with one impossible arc
 *  - replyall: a mail road through two scanner arches into a mailbox rack, three seal
 *             discs, a hidden siphon to a buried folder, and a wire held open
 *  - sharedlink: a boundary ring with site racks inside, a chat panel with a stranger
 *             outside, a DLP shield with one document slipping past, and a chain that breaks
 */
export type SceneId = "shield" | "gates" | "tower" | "network" | "campus" | "city" | "datapath" | "socfloor" | "portwall" | "hostcore" | "fstree" | "logriver" | "cipherlab" | "chrono" | "dissect" | "idgate" | "specimen" | "riskcore" | "patchline" | "chainlinks" | "zonewall" | "blackbox" | "mindlab" | "sightlines" | "webpath" | "baitshop" | "orchard" | "evtxtape" | "varlog" | "radar" | "intake" | "postmark" | "protostack" | "sealedbrief" | "sparekey" | "objectpipe" | "integrityladder" | "matrixwall" | "domaintree" | "wazuhflow" | "skyquery" | "noisefilter" | "tenantcloud" | "talon" | "storyline" | "detonation" | "nightqueue" | "coldcase" | "longdistance" | "denyall" | "lookup" | "generations" | "secondopinion" | "ignoreall" | "wirelevel" | "opensesame" | "baremetal" | "specialdelivery" | "tenantzero" | "replyall" | "sharedlink" | "facilitymail" | "facilitysoc" | "facilitynet" | "facilitytriage" | "facilitypacket" | "facilitytunnel" | "facilityentra" | "facilitydirectory" | "facilitychain" | "facilitymatrix" | "facilitybait" | "facilityhall" | "facilitycampus" | "facilitylastword" | "facilitybreadcrumb" | "facilitytabletop" | "facilityloosethread" | "facilitywhogoes" | "facilitypapertrail" | "facilitybadnews" | "facilityfrontdoor" | "facilityautopilot" | "facilitycrownjewels" | "facilityshareddrive" | "facilitymodelbehaviour" | "facilityhelpinghand" | "facilitylonggame" | "facilityfirstrule" | "facilitydeepquery" | "facilityexitroute" | "facilitysealedroom" | "facilitysidedoor" | "facilityreturnpath" | "facilitythreeheads" | "facilitypagefile" | "facilityprocesstree" | "facilitycoldvault" | "facilitydiamond";

/** cards: illustrated station cards above the scene. stage: the scene fills the
 *  screen, stations sit in a rail, the selected one in a bottom command bar.
 *  campus: the scene fills the screen with a facility status monitor beside it.
 *  lens: the scene fills the screen with a lens dial, one segment per station. */
export type LayoutId = "cards" | "stage" | "campus" | "lens" | "facility";

/** Which mechanic renders a task. Defaults by task type (see mechanicFor). */
export type MechanicId =
  | "intel_briefing"   // reading
  | "lock_terminal"    // question
  | "evidence_board"   // log_analysis
  | "triage_desk"      // analyst_choice
  | "vault_keypad"     // flag
  | "classic";         // any other type: the existing player inside a station frame

export interface Persona {
  name: string;
  role: string;
  /** Optional portrait (same-origin or bucket URL); initials are drawn without one. */
  photo?: string;
  /** A neutral in-world line. Must never hint at the verdict. */
  line: string;
}

/** The kind of place a station is; picks its illustration on the mission board. */
export type BuildingKind = "archive" | "factory" | "lab" | "office" | "vault" | "control" | "ticket"
  | "reception" | "emergency" | "wing" | "roof";

/**
 * Briefing labs: hands-on ways to learn a reading's material (inspect an
 * artifact, put steps in order, run a simulation, sort, match). They teach;
 * they are NOT graded and award no XP, so their answers may live in this
 * client-side config. Rule for authors: use example data that differs from
 * the room's graded tasks, so a lab never hands over a graded answer.
 */
export type BriefingLab = ({
      kind: "inspect";
      title: string;
      prompt: string;
      /** Caption over the artifact, e.g. "Raw headers · Show original". */
      artifact: string;
      items: { id: string; text: string; tag: string; tone: "trust" | "warn" | "info"; note: string }[];
    }
  | {
      kind: "sequence";
      title: string;
      prompt: string;
      /** Shown in this order; the learner taps them in `order`. */
      items: { id: string; text: string; note?: string }[];
      order: string[];
      doneNote: string;
    }
  | {
      kind: "simulate";
      title: string;
      prompt: string;
      checks: { name: string; question: string }[];
      scenarios: { id: string; label: string; detail: string; results: ("pass" | "fail")[]; why: string[]; verdict: string }[];
    }
  | {
      kind: "sort";
      title: string;
      prompt: string;
      buckets: { id: string; label: string }[];
      /** `hidden` = revealed on hover / focus / tap (e.g. a link's real href). */
      items: { id: string; text: string; hidden?: string; bucket: string; why: string }[];
    }
  | {
      kind: "match";
      title: string;
      prompt: string;
      pairs: { id: string; left: string; right: string; why: string }[];
    }
  | {
      /** Items ride a conveyor; route each into the right reactor before it
       *  reaches the end. A wrong reactor heats up and the item comes round again. */
      kind: "reactor";
      title: string;
      prompt: string;
      reactors: { id: string; label: string; sub: string }[];
      items: { id: string; text: string; reactor: string; why: string }[];
    }
  | {
      /** A line-up of suspects with dossiers; each round shows evidence and the
       *  learner picks who fits it. */
      kind: "lineup";
      title: string;
      prompt: string;
      suspects: { id: string; name: string; motive: string; skill: string; target: string }[];
      rounds: { id: string; evidence: string[]; suspect: string; why: string }[];
    }
  | {
      /** A realistic artifact (an email, a web page) with hidden hotspots: find
       *  every red flag; clicking a normal part says why it is fine. */
      kind: "hotspot";
      title: string;
      prompt: string;
      artifact: string;
      /** Shown once every flag is found, after "Every flag found." */
      finish?: string;
      parts: { id: string; text: string; flag: boolean; note: string; style?: "meta" | "subject" | "body" | "button" | "url"; /** shown in the status bar on hover, like a real link */ href?: string }[];
    }
  | {
      /** Everyday objects; scanning one with the lens reveals the computer
       *  inside it and what an attacker could do with it. */
      kind: "xray";
      title: string;
      prompt: string;
      objects: { id: string; label: string; icon: XrayIcon; inside: string; risk: string }[];
      doneNote: string;
    }
  | {
      /** Locked doors, one principle each: read the everyday example, then
       *  answer the door's check to open its lock. */
      kind: "locks";
      title: string;
      prompt: string;
      /** Shown after "All locks open." */
      finish?: string;
      locks: { id: string; letter: string; name: string; idea: string; example: string; check: { q: string; options: string[]; answer: number; why: string } }[];
    }
  | {
      /** Face-down cards with an everyday trick on each: flip one, then stamp it
       *  with the attack that works the same way. */
      kind: "tricks";
      title: string;
      prompt: string;
      attacks: { id: string; name: string }[];
      cards: { id: string; analogy: string; attack: string; real: string }[];
    }
  | {
      /** A sample alert in its source's native fields: scan each key field to
       *  learn what it tells an analyst, then read the one-line story. */
      kind: "anatomy";
      title: string;
      prompt: string;
      /** Caption over the alert, e.g. the product that raised it. */
      source: string;
      fields: { key: string; value: string; label?: string; note?: string }[];
      summary: string;
    }
  | {
      /** "What does it look like": realistic screens of real situations. The
       *  learner names what each screen shows, then numbered markers appear on
       *  the tell-tale parts of the screen with the explanation. */
      kind: "evidence";
      title: string;
      prompt: string;
      choices: { id: string; label: string }[];
      items: {
        id: string;
        /** Window title over the screen. */
        caption: string;
        screen: EvidenceScreen;
        answer: string;
        /** `at` names a part of the screen (see EvidenceScreen); shown in order. */
        callouts: { at: string; text: string }[];
      }[];
    }
  | {
      /** A chat window with a simulated assistant: the learner sends messages,
       *  each matched by a case-insensitive regex (first hit wins; `goal` limits a
       *  rule to one goal). A rule with `wins` completes the current goal. */
      kind: "chat";
      title: string;
      prompt: string;
      bot: string;
      botRole: string;
      greeting: string;
      fallback: string;
      rules: { match: string; reply: string; goal?: string; wins?: boolean }[];
      goals: { id: string; task: string; tries: string[]; why: string }[];
      doneNote: string;
      /** A winning rule reads everything said toward the current goal, not only the last message. */
      memory?: boolean;
    }
  | {
      /** A simulated shell (no real machine): the learner types commands, reads
       *  the output and answers each objective from it. Commands are matched by
       *  a case-insensitive regex; anything else prints the shell's own error. */
      kind: "terminal";
      title: string;
      prompt: string;
      shell: "cmd" | "powershell" | "bash";
      /** The prompt string, e.g. "C:\\Users\\analyst>" or "analyst@ws01:~$". */
      host: string;
      commands: { match: string; output: string; /** shown by `help` */ help?: string }[];
      objectives: { id: string; task: string; /** the command to suggest */ hint: string; answer: string[]; why: string }[];
    }
  | {
      /** Follow a lead across log sources: each step shows one log as a table
       *  (with a filter box); the learner clicks the row that answers the step. */
      kind: "trace";
      title: string;
      prompt: string;
      /** What the hunt starts from, e.g. the alert's external IP and time. */
      lead: string;
      steps: { id: string; ask: string; source: string; columns: string[]; rows: string[][]; answer: number; why: string; /** fact added to the case board */ learned: string }[];
    }
  | {
      /** Build a packet from the top down: at each layer pick the right header
       *  value; the packet grows one envelope at a time, then shows as a
       *  protocol tree like a packet analyser. */
      kind: "encap";
      title: string;
      prompt: string;
      /** The request being sent, e.g. "GET / to the intranet at 10.20.0.15:443". */
      story: string;
      layers: { id: string; layer: string; pdu: string; field: string; options: string[]; answer: number; why: string; tree: string; /** short value for the header chip, defaults to the answer */ chip?: string }[];
    }
  | {
      /** A SIEM-style alert queue: open each alert, read its fields and
       *  context, then take the action an analyst would. */
      kind: "queue";
      title: string;
      prompt: string;
      /** Console name in the title bar, e.g. "SIEM · Incidents". */
      console: string;
      actions: { id: string; label: string; tone: "close" | "escalate" | "contain" }[];
      alerts: { id: string; time: string; severity: "Low" | "Medium" | "High" | "Critical"; rule: string; entity: string; fields: { k: string; v: string }[]; context: string; answer: string; why: string }[];
    }
  | {
      /** A data table and questions answered by working it out (a count, a
       *  time difference, an average). */
      kind: "worksheet";
      title: string;
      prompt: string;
      caption: string;
      columns: string[];
      rows: string[][];
      questions: { id: string; q: string; hint: string; answer: string[]; why: string }[];
    }
  | {
      /** A packet capture in a packet-analyser view: packet list, a display
       *  filter, the protocol tree and the payload of the selected packet.
       *  Objectives are answered from what the packets show. */
      kind: "pcap";
      title: string;
      prompt: string;
      /** Capture file name in the title bar. */
      capture: string;
      packets: { no: number; time: string; src: string; dst: string; proto: string; len: number; info: string; tree: string[]; /** readable payload bytes, if any */ data?: string }[];
      objectives: { id: string; task: string; /** a display filter to suggest */ hint: string; answer: string[]; why: string }[];
    }
  | {
      /** Work a real job in a simulated analyst console, step by step: the layout,
       *  vocabulary and order of work of the real thing, with no logos. Looking around
       *  is free; a wrong action costs a life and says why. Step targets are
       *  menu:<id>, row:<id>, action:<id>, set:<field>:<value>, tree:<id>. */
      kind: "portal";
      title: string;
      prompt: string;
      skin: "azure" | "edr" | "vsphere" | "entra" | "exchange" | "defender";
      /** Top-bar label: generic, never a product name. */
      product: string;
      resource: string;
      tenant: string;
      home: string;
      menu: { group?: string; items: { id: string; label: string; /** Inventory tree indent, vsphere skin only. */ depth?: number }[] }[];
      pages: Record<string, {
        heading: string;
        commands?: { id: string; label: string }[];
        tiles?: { label: string; value: string }[];
        filters?: string[];
        note?: string;
        query?: string;
        table?: { columns: string[]; rows: { id: string; cells: string[]; tone?: "critical" | "high" | "medium" | "low" | "info"; record?: string }[] };
        /** vsphere skin: the inventory object this page belongs to, its tree node, and its tabs (ids are page ids). */
        object?: string;
        node?: string;
        tabs?: { id: string; label: string }[];
        tab?: string;
        sub?: { id: string; label: string }[];
      }>;
      records: Record<string, {
        id: string;
        title: string;
        strip?: { field: string; label: string; value: string; tone?: "critical" | "high" | "medium" | "low" | "info"; options?: string[] }[];
        facts: [string, string][];
        /** entra skin: facts per detail tab, keyed by action id. exchange skin: facts a flyout button opens. */
        panes?: Record<string, [string, string][]>;
        evidence?: [string, string][];
        entities?: { id: string; label: string; type: string; seen?: string }[];
        tactics?: string;
        timeline?: { time: string; text: string; tone?: "critical" | "high" | "medium" | "low" | "info" }[];
        actions?: { id: string; label: string }[];
        closing?: string[];
        logs?: { query: string; columns: string[]; rows: { id: string; cells: string[] }[] };
        tree?: { id: string; depth: number; name: string; detail: string; bad?: boolean; facts?: [string, string][] }[];
        /** defender skin: the incident graph. order is when a node appears on Play; x and y are percent. */
        graph?: { nodes: { id: string; label: string; type: "user" | "device" | "mail" | "ip" | "file" | "app"; x: number; y: number; order: number; alerted?: boolean; facts: [string, string][] }[]; edges: [string, string][] };
        /** defender skin: pending remediation actions. Targets are action:approve:<id> and action:reject:<id>. */
        remediation?: { id: string; entity: string; type: string; verdict: "Malicious" | "Suspicious" | "No threats found"; action: string; detail: string }[];
        /** defender skin: a status line shown once the action with this id has run. */
        banners?: Record<string, string>;
      }>;
      steps: { id: string; ask: string; hint: string; target: string; why: string }[];
      /** Why a wrong target is wrong, keyed by target. */
      traps: Record<string, string>;
      lesson: string;
    }
  | {
      /** Build a hunting query one line at a time in a console. Results are computed
       *  from the rows (see hunt.ts), so a wrong line shows what it really returns,
       *  then costs a life. Each rung has exactly one right line. */
      kind: "hunt";
      title: string;
      prompt: string;
      language: "KQL" | "SPL" | "EQL";
      /** Console title; defaults to Advanced hunting. */
      console?: string;
      /** The first line of the query: a table in `tables`. */
      start: string;
      goal: string;
      tables: HuntTable[];
      rungs: { id: string; ask: string; choices: { id: string; text: string; right?: boolean; why: string; apply: HuntStep }[] }[];
      /** Rows the finished query must return (checked by labIntegrity). */
      expect: number;
      lesson: string;
    }
  | {
      /** Arcade. Items drop toward what you guard; block or let through before
       *  they land. Wrong calls cost a life. 8 to 12 items; the clock tightens. */
      kind: "intercept";
      title: string;
      prompt: string;
      /** What is being guarded, a short name: "RKW-DC01", "the mail gateway". */
      protect: string;
      blockLabel?: string;
      passLabel?: string;
      /** Seconds for the first item to land (default 10). */
      seconds?: number;
      items: { id: string; text: string; sub?: string; bad: boolean; why: string }[];
      lesson: string;
    }
  | {
      /** Card duel. The attacker plays a move each round; the learner plays the
       *  one card that stops it. Played cards are gone; wrong cards cost a life.
       *  4 to 6 moves, and at least two more cards than moves. */
      kind: "duel";
      title: string;
      prompt: string;
      attacker: string;
      moves: { id: string; move: string; detail: string; counter: string; hint: string; why: string }[];
      cards: { id: string; name: string; effect: string }[];
      lesson: string;
    }
  | {
      /** Whodunit. Clues arrive one at a time; the learner strikes out suspects
       *  and accuses, with two accusations and fewer clues scoring better. */
      kind: "deduce";
      title: string;
      prompt: string;
      nameColumn: string;
      columns: string[];
      suspects: { id: string; name: string; cells: string[] }[];
      clues: string[];
      culprit: string;
      why: string;
    }
  | {
      /** Tune a detection: set the dials, deploy, see what it really caught.
       *  Results show only on deploy, and deploys are limited. */
      kind: "tune";
      title: string;
      prompt: string;
      eventColumn: string;
      dials: { id: string; label: string; short?: string; unit?: string; min: number; max: number; step: number; start: number; dir?: "above" | "below" }[];
      /** "all": every dial must trip (default behaviour of an AND rule). */
      mode?: "all" | "any";
      events: { id: string; label: string; bad: boolean; values: Record<string, number> }[];
      goal: { catch: number; maxFalse: number };
      deploys?: number;
      lesson: string;
    }
  | {
      /** Walk a real route across a map, hop by hop. A wrong hop costs a life
       *  and says why. Node x and y are percentages of the map. */
      kind: "pathway";
      title: string;
      prompt: string;
      goal: string;
      nodes: { id: string; label: string; sub?: string; x: number; y: number }[];
      edges: [string, string][];
      route: string[];
      /** Shown on reaching a node of the route. */
      notes: Record<string, string>;
      /** Shown on a wrong hop to this node. */
      traps: Record<string, string>;
      lesson: string;
    }
  | {
      /** Timed device: read the state, cut the one wire that fits. A wrong cut
       *  is a strike and costs ten seconds. 3 to 5 modules, 3 wires each. */
      kind: "defuse";
      title: string;
      prompt: string;
      device: string;
      seconds: number;
      rounds: { id: string; state: string; wires: { id: string; label: string }[]; cut: string; hint: string; why: string }[];
      lesson: string;
    }
  | {
      /** A live spread simulation on a network drawn fresh each run. Each turn the
       *  learner isolates one host, then the infection moves one link. Shows why
       *  you cut ahead of the spread, at the place the network narrows. */
      kind: "outbreak";
      title: string;
      prompt: string;
      hostPrefix: string;
      cols: number;
      rows: number;
      /** What must not fall, a short name: "the DC", "BACKUP". */
      crown: string;
      /** How it moves, finishing "It spreads by ...": "SMB with a stolen admin hash". */
      via: string;
      lesson: string;
    }
  | {
      /** Guess a code from a clue, with letter feedback after every try. Answers
       *  are letters and digits only: a term, port, event ID or technique ID. */
      kind: "codebreak";
      title: string;
      prompt: string;
      tries?: number;
      rounds: { id: string; clue: string; answer: string; why: string }[];
      lesson: string;
    }
  | {
      /** Blitz: rapid two-way calls against the clock, with a streak multiplier
       *  and a target. 12 to 16 cards. */
      kind: "rush";
      title: string;
      prompt: string;
      seconds?: number;
      /** Right answers needed to win. */
      target: number;
      trueLabel?: string;
      falseLabel?: string;
      cards: { id: string; text: string; answer: boolean; why: string }[];
      lesson: string;
    }
  | {
      /** Known-good copy beside a suspect copy: find the tampered lines. Wrong
       *  taps cost a life; decoys are harmless differences with their reason. */
      kind: "spotdiff";
      title: string;
      prompt: string;
      goodTitle: string;
      suspectTitle: string;
      good: string[];
      suspect: string[];
      /** Index into `suspect`. */
      diffs: { line: number; why: string }[];
      decoys?: { line: number; why: string }[];
      lesson: string;
      /** Top-bar instruction and wrong-tap text, when the copies are not good and tampered. */
      hud?: string;
      sameLine?: string;
      winTitle?: string;
    }) & {
  /** Numbered "how to play" steps shown above the lab; each kind has defaults. */
  howTo?: string[];
  /** What the learner needs before this lab: a few lines and one worked example, on data
   *  that differs from the lab and from the graded tasks. Open by default; `fold` starts
   *  it closed, for advanced rooms where trying first is the better way to learn. */
  primer?: { title: string; points: string[]; example?: { label: string; lines: string[] }; fold?: boolean };
};

/**
 * A realistic screen for the evidence lab. The comment on each type lists the
 * part names a callout can point `at`.
 */
export type EvidenceScreen =
  /** parts: site, title, rows */
  | { type: "leak"; site: string; title: string; meta: string; header: string[]; rows: string[][] }
  /** parts: file, hashes, change */
  | { type: "integrity"; tool: string; file: string; expected: string; current: string; changedBy: string; when: string; before: string; after: string }
  /** parts: state, graph, errors */
  | { type: "status"; service: string; state: string; errors: string; series: number[] }
  /** parts: url, banner */
  | { type: "defaced"; url: string; banner: string; text: string }
  /** parts: note, files, wallet */
  | { type: "ransom"; heading: string; note: string[]; files: string[]; wallet: string }
  /** parts: graph, sources */
  | { type: "traffic"; service: string; series: number[]; normal: number; sources: { ip: string; country: string; rate: string }[] }
  /** parts: network, url, error */
  | { type: "certwarn"; network: string; url: string; error: string; detail: string }
  /** parts: caller, request, pressure */
  | { type: "ticket"; id: string; caller: string; callerId: string; request: string; pressure: string; notes: string }
  /** parts: sender, text, link */
  | { type: "sms"; from: string; time: string; text: string; link: string }
  /** parts: query, results, rule */
  | { type: "siem"; product: string; query: string; rule: string; header: string[]; rows: string[][] }
  /** parts: tree, verdict */
  | { type: "edrtree"; host: string; verdict: string; nodes: { depth: number; name: string; detail: string; bad?: boolean }[] }
  /** parts: trigger, steps */
  | { type: "soarrun"; playbook: string; trigger: string; steps: { name: string; result: string; ok: boolean }[] }
  /** parts: indicator, score, sightings */
  | { type: "tip"; indicator: string; kind: string; score: string; tags: string[]; sightings: string[] };

/** Icons the x-ray lab can draw (lucide names). */
export type XrayIcon = "fridge" | "traffic" | "atm" | "pump" | "car" | "camera" | "phone" | "plant" | "thermostat";

export interface Station {
  id: string;
  label: string;
  /** One line under the label in the hub. */
  tagline: string;
  /** The room topics this station teaches, named the way the reading names
   *  them, so the learner always knows what a station covers. */
  topic?: string;
  building: BuildingKind;
  /** Existing task ids, in room order. Stations must be contiguous in the room. */
  taskIds: string[];
  /** The last station is the "boss": shown with a different marker in the hub. */
  boss?: boolean;
}

export interface RoomExperience {
  roomId: string;
  codename: string;
  theme: ThemeId;
  handler: { name: string; role: string };
  /** Typed out on the briefing screen, one line at a time. */
  briefing: string[];
  /** One-line mission statement under the title on the mission board. */
  mission: string;
  /** Rough time to play the whole operation, shown on the board footer. */
  estimate: string;
  /** Per-room tint for the board and the station art (CSS colours). */
  look?: { primary: string; secondary: string; warn: string };
  /** The room's 3D world and board layout. Defaults: shield + cards. */
  scene?: SceneId;
  layout?: LayoutId;
  stations: Station[];
  /**
   * Task id → hands-on labs. On a reading they teach the reading; on any other
   * task they run as an ungraded drill before the graded challenge.
   */
  briefings?: Record<string, BriefingLab[]>;
  /** Optional per-task persona (Triage Desk requester, etc.). */
  personas?: Record<string, Persona>;
  /**
   * Short story films: `intro` plays before the first station, `afterStation`
   * plays when that station is first cleared (keyed by station id). Story only,
   * never a graded answer. Each plays once per viewer and can be replayed from
   * the board.
   */
  story?: { intro?: StoryClip; afterStation?: Record<string, StoryClip> };
}

/** One story film: same-origin or Supabase-hosted MP4 plus a poster frame. */
export interface StoryClip {
  title: string;
  src: string;
  poster?: string;
}
