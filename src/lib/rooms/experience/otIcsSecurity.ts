import type { RoomExperience } from "./types";

// "Operation Long Game" for the "ot-ics-security" room.
// Script: docs/campaign/72-ot-ics-security.md.
// Station task ids follow the room's own task order (see getRoomExperience).
//
// Fellside Water and Power (fictional small utility), mentor Tariq Lindholm, OT Security Engineer.
// The graded tasks are Meridian Valley's file, which Tariq uses as the test.
// Signature: Safety Before Containment. The IT reflex (isolate the host) can stop a process, so
// the outbreak and the intercept that follows it weigh every cut against safety and availability.
// A pathway walks the Purdue levels, and a pcap reads a real Modbus write byte by byte.
// Arcade mix: deduce + intercept + outbreak + pathway.
// Lab data differs from the graded tasks: Fellside's hydro intake gate and plc-gate-02, never a
// dosing pump, plc-dose-03/04 or ENG-WS-02. Addresses are 192.168.40-44.x, never 172.20.5.x or
// 10.50.12.77. The lab write is function code 6 to register 40108 (wire address 107) with value
// 550, never function code 16 to wire address 19 or 29. The anatomy is a READ record, never a write.
// The worksheet shows ports only as row data and never asks them (q1, m1). The sort on Command Message (named without its ID, ot-f1's answer),
// T0836 and T0831 uses DNP3 and S7 events at Fellside, never the Ukraine substation (q2). The
// intercept's cuts are on FS-COMM-07 and the Fellside plant, not a corporate VLAN source (q3).
// The sequence is a nine-week Fellside intrusion with more steps than the chain in q4.

export const OT_ICS_SECURITY: RoomExperience = {
  roomId: "ot-ics-security",
  codename: "Operation Long Game",
  theme: "longgame",
  handler: { name: "Tariq Lindholm", role: "OT Security Engineer, Fellside Water and Power" },
  briefing: [
    "Fellside Water and Power. One reservoir, one treatment works, a small hydro station, and a handful of people who keep 23,000 homes in water and light.",
    "At 03:12 on Sunday the hydro intake gate moved on its own. Nobody was at the panel, and the night operator put it back by hand.",
    "Corporate IT wants every plant host isolated by lunchtime. Tariq Lindholm wants to know first what each of those hosts is keeping running.",
    "Learn the plant, read the write on the wire, weigh every cut against the process, then rebuild the whole chain. Tariq tests you on a neighbour's file: the Meridian Valley case.",
  ],
  mission: "Sort what a plant fears, walk the Purdue levels, name the ways in, open the case files, read a Modbus write on the wire, find who moved the gate, pick a sensor that cannot hurt the plant, weigh every cut against the process, then rebuild the chain.",
  estimate: "~65 min",
  look: { primary: "#ff8c42", secondary: "#8fd3e8", warn: "#ff4d6d" },
  scene: "facilitylonggame",
  layout: "facility",
  stations: [
    {
      id: "floor",
      label: "The Plant Floor",
      topic: "OT and ICS · the AIC inversion · PLC, RTU, DCS, HMI, SCADA · the Purdue Model · industrial protocols · how exposure gets exploited",
      tagline: "Nothing here reboots quietly",
      building: "control",
      taskIds: ["ot-r0", "ot-r1", "ot-r2", "ot-q1", "ot-m1"],
    },
    {
      id: "cases",
      label: "The Case Files",
      topic: "Stuxnet · TRITON and safety systems · Industroyer · Oldsmar · command, value and effect in ATT&CK for ICS",
      tagline: "It has happened before",
      building: "archive",
      taskIds: ["ot-r3", "ot-r4", "ot-q2"],
    },
    {
      id: "write",
      label: "The Write",
      topic: "Sweeps and writes on the wire · Modbus function codes · reading Zeek records · who has history with a controller",
      tagline: "Same port, opposite verdict",
      building: "lab",
      taskIds: ["ot-r5", "ot-la1", "ot-ac1"],
    },
    {
      id: "containment",
      label: "Safe Containment",
      topic: "Why a PLC takes no agent · SPAN and TAP · Zeek and Suricata · allowlisting · the Industrial DMZ · responding without breaking the plant",
      tagline: "What does this host keep running?",
      building: "factory",
      taskIds: ["ot-r6", "ot-r7", "ot-q3"],
    },
    {
      id: "longgame",
      label: "The Long Game",
      topic: "The ICS kill chain from first foothold to physical effect",
      tagline: "Nine weeks, one register",
      building: "vault",
      taskIds: ["ot-q4", "ot-f1"],
      boss: true,
    },
  ],
  personas: {
    "ot-q1": { name: "Tariq Lindholm", role: "OT Security Engineer", line: "This is Meridian Valley's file, page one. Start with what's on the wire." },
    "ot-m1": { name: "Tariq Lindholm", role: "OT Security Engineer", line: "You'll meet all four on a plant network. Put names to them." },
    "ot-q2": { name: "Tariq Lindholm", role: "OT Security Engineer", line: "An investigator's notes from a real case. Read both steps slowly." },
    "ot-la1": { name: "Tariq Lindholm", role: "OT Security Engineer", line: "There's no agent on that segment. All you have is what the sensor heard." },
    "ot-ac1": { name: "Tariq Lindholm", role: "OT Security Engineer", line: "Writes in the small hours, one controller. Tell me what you make of it." },
    "ot-q3": { name: "Tariq Lindholm", role: "OT Security Engineer", line: "Operations is on the phone. What do you tell them?" },
    "ot-q4": { name: "Tariq Lindholm", role: "OT Security Engineer", line: "Put Meridian's whole chain in order for me." },
    "ot-f1": { name: "Tariq Lindholm", role: "OT Security Engineer", line: "One ID for the case file." },
  },
  briefings: {
    // ── Reading 0: why OT is a different discipline ──
    "ot-r0": [
      {
        kind: "sort",
        title: "What Would Wake the Plant?",
        prompt: "IT trains you to protect Confidentiality, Integrity and Availability, in that order. Fellside's OT (Operational Technology), the kit that moves real water and real gates, runs on a different order. Sort the night operator's worries by what each one damages.",
        buckets: [
          { id: "a", label: "Availability: the process stops" },
          { id: "i", label: "Integrity: a value can't be trusted" },
          { id: "c", label: "Confidentiality: someone reads it" },
        ],
        items: [
          { id: "s1", text: "A controller restarts in the middle of a filter backwash", bucket: "a", why: "A plant can't just reboot and carry on. An unplanned stop of a physical process can do physical harm, so Availability comes first in OT." },
          { id: "s2", text: "The screen shows the reservoir at 62% while the real level is 81%", bucket: "i", why: "The operator acts on what the screen says. A false number is the Integrity problem: does the value match the physical world?" },
          { id: "s3", text: "An outsider reads the turbine's hourly output figures", bucket: "c", why: "Almost nobody at a utility loses sleep over someone reading a flow rate. Confidentiality is a distant third." },
          { id: "s4", text: "The hydro station trips offline during an evening peak", bucket: "a", why: "Homes lose power whatever the cause. The first question in OT is whether the process keeps running safely." },
          { id: "s5", text: "A gate setpoint is changed from 40% to 65% with no operator at the panel", bucket: "i", why: "Changing a value is what everybody here fears. It moves something real, so Integrity sits second, well above Confidentiality." },
          { id: "s6", text: "A contractor copies the plant's network diagram", bucket: "c", why: "It matters, because diagrams help an intruder plan. But nothing has physically changed yet, which is why OT writes the triad as AIC." },
          { id: "s7", text: "The pumps at the treatment works stop and the town's pressure falls", bucket: "a", why: "A data breach costs money and trust. This reaches people's taps. That difference in consequence is the reason for the inverted order." },
        ],
      },
      {
        kind: "inspect",
        title: "Why the Plant Looks Out of Date",
        prompt: "Fellside's control network register reads like a list of mistakes to an IT eye. Tariq says none of it is an accident. Open each line and read why it is the way it is.",
        artifact: "Fellside asset register · control network",
        items: [
          { id: "n1", text: "Scope: OT, physical gates, pumps and breakers", tag: "OT", tone: "info", note: "OT senses and controls physical equipment. An ICS (Industrial Control System) is the automation built on it that runs a whole process, such as a water system or a power station." },
          { id: "n2", text: "FS-HMI-01 · Windows 7 · vendor-certified build", tag: "Old on purpose", tone: "trust", note: "Safety certification and vendor support are tied to one exact, tested software configuration. Upgrading means retesting the whole thing, so an old OS can be the supported state." },
          { id: "n3", text: "plc-turb-01 · patch window: annual outage, September", tag: "One chance a year", tone: "warn", note: "Some systems get patched once a year, in a single planned outage. A monthly patch cycle would mean stopping a live process every month." },
          { id: "n4", text: "plc-gate-02 · endpoint agent: none, not possible", tag: "No agent", tone: "warn", note: "There's no EDR, antivirus or logging agent on a controller. Nothing that you learned to pivot through on a Windows host exists down here." },
          { id: "n5", text: "If it fails: spill risk at the intake", tag: "Consequence", tone: "warn", note: "This column has no IT equivalent. A failure here can be physical, even a risk to life, and that's why availability and integrity outrank secrecy." },
        ],
      },
    ],
    // ── Reading 1: the devices and the Purdue Model ──
    "ot-r1": [
      {
        kind: "match",
        title: "Who Does What on the Floor",
        prompt: "Tariq walks you round the plant. Five terms you'll hear on every call: match each one to what it really is at Fellside.",
        pairs: [
          { id: "m1", left: "PLC (Programmable Logic Controller)", right: "Runs one fixed program in a loop, dozens of times a second: plc-gate-02 reads the gate's sensors and drives its motor", why: "Read inputs, run logic, write outputs, forever. It's a small rugged computer with one job." },
          { id: "m2", left: "RTU (Remote Terminal Unit)", right: "Built for the far end of a long, thin link: rtu-res-04 reports the reservoir level from the dam", why: "Much like a PLC, but made for long-distance telemetry over low-bandwidth or serial links." },
          { id: "m3", left: "DCS (Distributed Control System)", right: "Many controllers under one configuration across a whole site: what a refinery runs, and Fellside is too small to need", why: "It's the PLC idea scaled up to a large continuous process." },
          { id: "m4", left: "HMI (Human-Machine Interface)", right: "The screen an operator watches, almost always a Windows PC: FS-HMI-01 in the control room", why: "It shows live values and lets an authorised person issue commands. That Windows PC is where IT skills start to apply again." },
          { id: "m5", left: "SCADA (Supervisory Control and Data Acquisition)", right: "Not a device: the whole arrangement of screens, servers and links that lets a small team supervise a wide area", why: "People say 'the SCADA' as if it were a box. It's an architecture." },
        ],
      },
      {
        kind: "pathway",
        title: "Down the Purdue Levels",
        prompt: "An engineer at a corporate desk has an approved change for the intake gate's controller. Walk that change down the Purdue Model by the approved route, the only way Tariq will sign off. A wrong hop costs a life.",
        goal: "Reach the intake gate by the approved route",
        nodes: [
          { id: "desk", label: "FS-PC-117", sub: "Level 5 · Enterprise", x: 14, y: 12 },
          { id: "billing", label: "Billing and ERP", sub: "Level 4 · Business planning", x: 54, y: 12 },
          { id: "jump", label: "FS-JUMP-01", sub: "Level 3.5 · Industrial DMZ", x: 34, y: 34 },
          { id: "hist", label: "FS-HIST-01", sub: "Level 3 · Site operations", x: 72, y: 36 },
          { id: "vendor", label: "Vendor support PC", sub: "One cable in each zone", x: 11, y: 54 },
          { id: "eng", label: "FS-ENG-01", sub: "Level 2 · Engineering", x: 34, y: 56 },
          { id: "hmi", label: "FS-HMI-01", sub: "Level 2 · Operator screen", x: 66, y: 58 },
          { id: "plc", label: "plc-gate-02", sub: "Level 1 · Basic control", x: 34, y: 73 },
          { id: "rtu", label: "rtu-res-04", sub: "Level 1 · Field telemetry", x: 66, y: 80 },
          { id: "gate", label: "Intake gate", sub: "Level 0 · Physical process", x: 34, y: 90 },
        ],
        edges: [["desk", "billing"], ["desk", "jump"], ["desk", "vendor"], ["vendor", "eng"], ["billing", "hist"], ["jump", "hist"], ["jump", "eng"], ["hist", "hmi"], ["eng", "hmi"], ["eng", "plc"], ["eng", "rtu"], ["plc", "gate"]],
        route: ["desk", "jump", "eng", "plc", "gate"],
        notes: {
          desk: "Levels 4 and 5 are IT: mail, internet, business systems. Everything from Level 3 down is OT.",
          jump: "Level 3.5 was not in the original 1990s model, but modern OT security treats it as essential: every hop between IT and OT crosses this logged chokepoint.",
          eng: "Level 2 holds the screens and stations that supervise a plant area. This one is allowed to change controllers.",
          plc: "Level 1 is the controllers: PLCs, RTUs and DCS controllers. The change lands here.",
          gate: "Level 0 is the physical process: sensors, actuators, pumps and this gate. Nothing below it but water.",
        },
        traps: {
          billing: "Level 4 holds billing and ERP. It's a business system and there's no business reason for it to reach a controller.",
          vendor: "It works, and that's the problem. One machine in both zones skips Level 3.5 entirely, so nothing logs or filters the crossing. Real intrusions have used exactly this.",
          hist: "The historian at Level 3 records process values for reports. It stores what happened. It's not a route for changing anything.",
          hmi: "Same level, wrong tool. The operator screen runs the plant minute to minute. An approved change to a controller goes through the engineering station.",
          rtu: "A controller on the right level, but it reports the reservoir. It has no part in driving the intake gate.",
        },
        lesson: "Read the Purdue Model from the top: 5 and 4 are IT, 3.5 is the Industrial DMZ, 3 is site operations and the historian, 2 is HMIs and SCADA servers, 1 is controllers, 0 is the physical process. Any path that gets from IT to OT without crossing 3.5 is the thing to look for. NIST SP 800-82 Revision 3 builds on the same picture.",
      },
    ],
    // ── Reading 2: protocols with no front door ──
    "ot-r2": [
      {
        kind: "worksheet",
        title: "What the Sensor Hears",
        prompt: "A week of traffic from Fellside's passive sensor, FS-SENSOR-01, summed up by protocol. Tariq reads this table before anything else. Work out the two things that stand out.",
        caption: "FS-SENSOR-01 · protocol summary · last 7 days",
        columns: ["Protocol", "Port", "Typical use", "From", "To", "Requests"],
        rows: [
          ["Modbus/TCP", "502/TCP", "Reads and writes registers. The most widely deployed industrial protocol", "FS-HMI-01", "plc-gate-02", "20,160"],
          ["S7comm", "102/TCP", "Siemens S7 PLC engineering and programming", "FS-ENG-01", "plc-turb-01", "214"],
          ["DNP3 (Distributed Network Protocol)", "20000/TCP", "Utility telemetry between an RTU and a SCADA master", "FS-SCADA-01", "rtu-res-04", "10,080"],
          ["EtherNet/IP (built on CIP)", "44818/TCP, 2222/UDP", "Rockwell factory automation", "FS-VEND-02", "Test rig 192.168.44.50", "5,040"],
        ],
        questions: [
          { id: "odd", q: "Fellside's inventory lists no Rockwell or Allen-Bradley equipment. Which protocol should not be here?", hint: "Compare the Typical use column with the inventory.", answer: ["EtherNet/IP", "EtherNetIP", "EtherNet", "CIP"], why: "It turned out to be a vendor's bench rig, but a protocol that doesn't match the inventory is a finding until somebody explains it. In OT, knowing what should be on the wire is half of detection." },
          { id: "eng", q: "Which row is an engineering conversation rather than routine polling?", hint: "Polling is constant. Look at the Requests column.", answer: ["S7comm", "S7"], why: "Polling repeats all day, so its counts run high. A few hundred requests to one controller means a person doing a job. Rare, bursty traffic to a controller is what you read closely." },
        ],
      },
      {
        kind: "sort",
        title: "What Stops a Command?",
        prompt: "These protocols were built for locked rooms on closed serial links. So what happens to a request when it reaches a controller? Sort each case by what really happens to it.",
        buckets: [
          { id: "obey", label: "The controller obeys" },
          { id: "error", label: "The controller answers with an error" },
          { id: "net", label: "It never reaches the controller" },
        ],
        items: [
          { id: "w1", text: "FS-HMI-01 asks plc-gate-02 for two holding registers, as it does all day", bucket: "obey", why: "Routine polling. Nothing about the request says who sent it, and nothing needs to." },
          { id: "w2", text: "A laptop plugged into the control switch asks to write a holding register", bucket: "obey", why: "There's no username, password or encryption in the protocol. Any host that can route a packet to the port has the same authority as the engineering station." },
          { id: "w3", text: "A request names a register that doesn't exist on this controller", bucket: "error", why: "Modbus exception 02, Illegal Data Address. The controller refused the request because of what it asked for, not because of who asked." },
          { id: "w4", text: "A host sends a function code this controller doesn't implement", bucket: "error", why: "Exception 01, Illegal Function. Again the fault is in the request. An error like this never means the sender was checked." },
          { id: "w5", text: "A corporate PC tries port 502 on the gate controller, and the firewall has no rule for it", bucket: "net", why: "This is the only thing in the list that judged the sender, and it was the network, not the controller." },
          { id: "w6", text: "A write from a brand-new source, sent over a route the firewall allows", bucket: "obey", why: "New to you, but the controller has no idea what's new. Remembering who usually talks is the job of your sensor, not of the protocol." },
          { id: "w7", text: "A session from the internet stops at the Level 3.5 firewall", bucket: "net", why: "Air gaps were the old answer to the missing authentication. Now that historians, vendors and laptops cross zones, the network boundary has to do that work." },
        ],
      },
      {
        kind: "reactor",
        title: "Name the Way In",
        prompt: "ATT&CK for ICS is MITRE's matrix for industrial attacks. Six ways Tariq has seen plants exposed: send each one to the technique that describes it.",
        reactors: [
          { id: "t0883", label: "T0883 Internet Accessible Device", sub: "Initial Access (TA0108). The device itself faces the internet" },
          { id: "t1694", label: "T1694.001 Insecure Credentials: Default Credentials (formerly T0812)", sub: "Persistence (TA0110) and Lateral Movement (TA0109). A factory login nobody changed" },
          { id: "t0886", label: "T0886 Remote Services", sub: "Initial Access (TA0108) and Lateral Movement (TA0109). A remote session" },
        ],
        items: [
          { id: "e1", text: "A 4G router gives a pumping station's controller a public address, behind a short password", reactor: "t0883", why: "The asset is reachable straight from the internet through a weak remote-access function. No exploit was needed." },
          { id: "e2", text: "Already inside, an intruder signs in to a second panel with the password printed in the vendor manual", reactor: "t1694", why: "The login is set at the factory and published. Once someone reaches a device, they log in and move to the next." },
          { id: "e3", text: "From a breached corporate PC, an RDP session opens on the plant's jump host", reactor: "t0886", why: "No plant device faces the internet here. The session starts inside IT and moves on, so this is Remote Services as Lateral Movement." },
          { id: "e4", text: "An outsider's first step: a stolen vendor account opens RDP from the vendor's own network", reactor: "t0886", why: "The same mechanism as the RDP pivot, but here it's the first foothold. MITRE lists one technique under two tactics because the role decides the tactic, not the protocol." },
          { id: "e5", text: "A weir's data logger answers on a public IP with its web page open", reactor: "t0883", why: "Exposed for convenience, whether anyone meant to or not. Ask whether the device itself can be reached from the internet." },
          { id: "e6", text: "Panel by panel, the same published password keeps working", reactor: "t1694", why: "Nothing was broken. Nobody changed what the vendor shipped, on any of them." },
        ],
      },
    ],
    // ── Reading 3: when malware targets the process ──
    "ot-r3": [
      {
        kind: "lineup",
        title: "The Case Files",
        prompt: "Tariq keeps five files on the shelf behind the desk: the incidents this whole field is built on. Each round reads out evidence from one of them. Name the case, then open its dossier.",
        suspects: [
          { id: "stuxnet", name: "Stuxnet", motive: "Wreck centrifuges without being noticed", skill: "Changed drive frequencies and fed the HMI false readings", target: "Siemens S7-300 PLCs at Natanz, found 2010" },
          { id: "triton", name: "TRITON", motive: "Reach the system that shuts a plant down safely", skill: "RDP jump boxes and a poorly configured OT firewall", target: "Triconex Safety Instrumented System, Saudi petrochemical plant, 2017" },
          { id: "industroyer", name: "Industroyer", motive: "Cut the power", skill: "Payload modules speaking relays' native protocols", target: "Transmission substation outside Kyiv, 2016" },
          { id: "oldsmar", name: "Oldsmar", motive: "Unclear, and later reporting raised human error", skill: "Probable desktop-sharing software, weak passwords, an old OS", target: "Florida water treatment facility, 2021" },
          { id: "bowman", name: "Bowman Avenue Dam", motive: "Access, as far as the record shows", skill: "A cellular modem with a brute-forceable password", target: "A small dam's control system" },
        ],
        rounds: [
          { id: "r1", evidence: ["Network bursts reached frequency converter drives", "Motor speed went outside safe bounds", "Operators' screens looked normal throughout"], suspect: "stuxnet", why: "MITRE's documented example of T0836, Modify Parameter (Impair Process Control, TA0106): a value the process depends on, pushed out of bounds, while the view is falsified." },
          { id: "r2", evidence: ["A bug in the malware caused an unplanned shutdown", "Engineers first assumed a mechanical fault", "The malware has three names: one each from Mandiant, Dragos and CISA"], suspect: "triton", why: "HatMan and TRISIS are its other names. A Safety Instrumented System is separate hardware whose only job is to stop the process safely. Lateral movement in OT, T0886 in this case, can have a worse destination than the main controllers, so an analyst must watch those too." },
          { id: "r3", evidence: ["A device sat on both the IT and ICS networks", "The malware needed no HMI: it talked to the devices directly", "Part of a city lost power for about an hour"], suspect: "industroyer", why: "Sandworm Team's attack crossed the boundary through a dual-homed device, then used the devices' own protocols. Those protocols didn't ask who was sending." },
          { id: "r4", evidence: ["A target concentration went from 100 to 11,100 parts per million", "An operator watched it happen and reversed it", "A joint advisory, AA21-042A, followed"], suspect: "oldsmar", why: "The pattern T0883 and T0886 describe. Later statements raised human error, so check a case's sourcing. A government advisory doesn't make every retelling settled." },
          { id: "r5", evidence: ["The way in was a phone-network link, not an office network", "The only barrier could be guessed"], suspect: "bowman", why: "MITRE's example for T0883, Internet Accessible Device: an ICS asset directly reachable through weakly protected remote access." },
        ],
      },
    ],
    // ── Reading 4: command, value, effect ──
    "ot-r4": [
      {
        kind: "sort",
        title: "Message, Value or Effect?",
        prompt: "One bad night can carry three ATT&CK for ICS techniques, and analysts mix them up. Tariq ran a tabletop for the hydro side. Sort each line by what you're looking at: a message on the wire, a value in a controller, or a change in the physical world.",
        buckets: [
          { id: "msg", label: "The message: Unauthorized Message: Command Message, Impair Process Control (TA0106)" },
          { id: "val", label: "The value: T0836 Modify Parameter, Impair Process Control (TA0106)" },
          { id: "eff", label: "The effect: T0831 Manipulation of Control, Impact (TA0105)" },
        ],
        items: [
          { id: "t1", text: "A DNP3 Direct Operate reaches the feeder recloser from a host that has never sent one", bucket: "msg", why: "A command the device was never meant to accept from that source. You're looking at the message itself, whatever it goes on to cause." },
          { id: "t2", text: "The feeder recloser opens and the village line drops", bucket: "eff", why: "This is the result: the state of the physical process changed. It's a separate fact from the message that caused it." },
          { id: "t3", text: "The turbine's overspeed limit in the controller goes from 1,050 to 1,400 rpm", bucket: "val", why: "A stored setting that the process depends on, moved out of bounds. Stuxnet is MITRE's example of the same thing." },
          { id: "t4", text: "An S7 Write Var arrives at the pump controller from the print server", bucket: "msg", why: "The wrong source for this kind of message. Impair Process Control is the tactic: the command acts on control itself." },
          { id: "t5", text: "Reservoir outflow climbs as the gate opens, with nobody at the panel", bucket: "eff", why: "Impact is the tactic for what the process actually did. Reports often name only the effect and lose the step that caused it." },
          { id: "t6", text: "The gate's maximum opening in the controller is raised from 70% to 95%", bucket: "val", why: "The setting is now wrong, whether or not the water has moved yet. That's why it's a parameter and not an effect." },
        ],
      },
    ],
    // ── Reading 5: an intrusion on the wire ──
    "ot-r5": [
      {
        kind: "anatomy",
        title: "Anatomy of a Modbus Record",
        prompt: "This is what Fellside's passive sensor decodes, with no agent on either end. Here's a boring record: the operator's screen reading the gate setpoint. Learn what each field proves and what it doesn't, because the same fields will decide a harder case.",
        source: "Zeek · modbus records · FS-SENSOR-01",
        fields: [
          { key: "event.dataset", value: "zeek.modbus", label: "Log" },
          { key: "source.ip", value: "192.168.40.11", label: "Who asked", note: "FS-HMI-01, inside the 192.168.40.0/24 engineering block. A private address means internal. A TCP session completed its handshake, so it isn't a spoofed source." },
          { key: "source.port", value: "49822", note: "A client always uses a high, temporary port and connects to 502 on the server. It tells you nothing." },
          { key: "destination.ip", value: "192.168.41.22", label: "Controller", note: "plc-gate-02." },
          { key: "destination.port", value: "502", note: "Reads and writes share this port. A port never tells you what happened." },
          { key: "zeek.modbus.func", value: "READ_HOLDING_REGISTERS", label: "Direction", note: "The only field that says what kind of exchange this was. Function codes 3 and 4 read. 6 and 16 write registers, and 5 and 15 write coils." },
          { key: "zeek.modbus.unit_id", value: "1", note: "Which unit behind this address. Usually 1 on a single PLC." },
          { key: "zeek.modbus.address", value: "107", label: "Where", note: "The wire address, counted from 0. Engineers call this register 40108, the 4xxxx form of a holding register, and a log may show either. Holding registers are read as often as they're written, so this doesn't give you direction." },
          { key: "zeek.modbus.quantity", value: "1", note: "How many registers." },
          { key: "zeek.modbus.values", value: "400", label: "Data", note: "The gate setpoint: 40.0%. Values show up in read responses too, so seeing a number doesn't mean anything was written." },
          { key: "zeek.modbus.request_response", value: "RESPONSE", note: "Every exchange is a REQUEST then a RESPONSE, reads included." },
          { key: "session.duration", value: "0.019", note: "19 milliseconds, as any single exchange would be, from anyone. Short proves nothing." },
        ],
        summary: "Read the function code for what was done, and the source and its history for who did it. Port, address, values, REQUEST and duration all look alike on a good day and a bad one. One more thing to keep in mind: a register write changes one value. A change to the PLC's program is more serious, because it survives a power cycle and quietly redefines what normal means.",
      },
      {
        kind: "pcap",
        title: "Read the Write",
        prompt: "Sunday, 03:11. Tariq pulled this capture from the sensor's mirror port on the control switch. Filter it, select packets and read the layers: find out what happened to the gate. FS-HMI-01 is 192.168.40.11.",
        capture: "fs-sensor-01_sun_0311.pcap",
        packets: [
          { no: 1, time: "03:11:40.102", src: "192.168.40.11", dst: "192.168.41.22", proto: "Modbus/TCP", len: 66, info: "Query: Trans: 1204; Unit: 1, Func: 3: Read Holding Registers", tree: ["Internet Protocol Version 4, Src: 192.168.40.11, Dst: 192.168.41.22", "Transmission Control Protocol, Src Port: 49822, Dst Port: 502", "Modbus/TCP: Transaction Identifier: 1204, Protocol Identifier: 0, Length: 6, Unit Identifier: 1", "Modbus: Function Code: Read Holding Registers (3), Reference Number: 107, Word Count: 1"], data: "04 b4 00 00 00 06 01 03 00 6b 00 01" },
          { no: 2, time: "03:11:40.121", src: "192.168.41.22", dst: "192.168.40.11", proto: "Modbus/TCP", len: 65, info: "Response: Trans: 1204; Unit: 1, Func: 3: Read Holding Registers", tree: ["Internet Protocol Version 4, Src: 192.168.41.22, Dst: 192.168.40.11", "Transmission Control Protocol, Src Port: 502, Dst Port: 49822", "Modbus/TCP: Transaction Identifier: 1204, Protocol Identifier: 0, Length: 5, Unit Identifier: 1", "Modbus: Function Code: Read Holding Registers (3), Byte Count: 2", "Register 107 (UINT16): 400"], data: "04 b4 00 00 00 05 01 03 02 01 90" },
          { no: 3, time: "03:11:48.310", src: "192.168.44.87", dst: "192.168.41.21", proto: "TCP", len: 60, info: "50311 → 502 [SYN] Seq=0 Win=8192 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.21", "Transmission Control Protocol, Src Port: 50311, Dst Port: 502, Flags: 0x002 (SYN)"] },
          { no: 4, time: "03:11:48.322", src: "192.168.41.21", dst: "192.168.44.87", proto: "TCP", len: 60, info: "502 → 50311 [SYN, ACK] Seq=0 Ack=1 Win=4096 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.41.21, Dst: 192.168.44.87", "Transmission Control Protocol, Src Port: 502, Dst Port: 50311, Flags: 0x012 (SYN, ACK)"] },
          { no: 5, time: "03:11:48.323", src: "192.168.44.87", dst: "192.168.41.21", proto: "TCP", len: 60, info: "50311 → 502 [RST] Seq=1 Win=0 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.21", "Transmission Control Protocol, Src Port: 50311, Dst Port: 502, Flags: 0x004 (RST)"] },
          { no: 6, time: "03:11:48.905", src: "192.168.44.87", dst: "192.168.41.22", proto: "TCP", len: 60, info: "50312 → 502 [SYN] Seq=0 Win=8192 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.22", "Transmission Control Protocol, Src Port: 50312, Dst Port: 502, Flags: 0x002 (SYN)"] },
          { no: 7, time: "03:11:48.917", src: "192.168.41.22", dst: "192.168.44.87", proto: "TCP", len: 60, info: "502 → 50312 [SYN, ACK] Seq=0 Ack=1 Win=4096 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.41.22, Dst: 192.168.44.87", "Transmission Control Protocol, Src Port: 502, Dst Port: 50312, Flags: 0x012 (SYN, ACK)"] },
          { no: 8, time: "03:11:48.918", src: "192.168.44.87", dst: "192.168.41.22", proto: "TCP", len: 60, info: "50312 → 502 [RST] Seq=1 Win=0 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.22", "Transmission Control Protocol, Src Port: 50312, Dst Port: 502, Flags: 0x004 (RST)"] },
          { no: 9, time: "03:11:49.470", src: "192.168.44.87", dst: "192.168.41.23", proto: "TCP", len: 60, info: "50313 → 502 [SYN] Seq=0 Win=8192 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.23", "Transmission Control Protocol, Src Port: 50313, Dst Port: 502, Flags: 0x002 (SYN)"] },
          { no: 10, time: "03:11:49.482", src: "192.168.41.23", dst: "192.168.44.87", proto: "TCP", len: 60, info: "502 → 50313 [SYN, ACK] Seq=0 Ack=1 Win=4096 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.41.23, Dst: 192.168.44.87", "Transmission Control Protocol, Src Port: 502, Dst Port: 50313, Flags: 0x012 (SYN, ACK)"] },
          { no: 11, time: "03:11:49.483", src: "192.168.44.87", dst: "192.168.41.23", proto: "TCP", len: 60, info: "50313 → 502 [RST] Seq=1 Win=0 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.23", "Transmission Control Protocol, Src Port: 50313, Dst Port: 502, Flags: 0x004 (RST)"] },
          { no: 12, time: "03:11:50.041", src: "192.168.44.87", dst: "192.168.41.24", proto: "TCP", len: 60, info: "50314 → 502 [SYN] Seq=0 Win=8192 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.24", "Transmission Control Protocol, Src Port: 50314, Dst Port: 502, Flags: 0x002 (SYN)"] },
          { no: 13, time: "03:11:50.612", src: "192.168.44.87", dst: "192.168.41.25", proto: "TCP", len: 60, info: "50315 → 502 [SYN] Seq=0 Win=8192 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.25", "Transmission Control Protocol, Src Port: 50315, Dst Port: 502, Flags: 0x002 (SYN)"] },
          { no: 14, time: "03:11:51.188", src: "192.168.44.87", dst: "192.168.41.26", proto: "TCP", len: 60, info: "50316 → 502 [SYN] Seq=0 Win=8192 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.26", "Transmission Control Protocol, Src Port: 50316, Dst Port: 502, Flags: 0x002 (SYN)"] },
          { no: 15, time: "03:12:02.610", src: "192.168.44.87", dst: "192.168.41.22", proto: "TCP", len: 60, info: "50320 → 502 [SYN] Seq=0 Win=8192 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.22", "Transmission Control Protocol, Src Port: 50320, Dst Port: 502, Flags: 0x002 (SYN)"] },
          { no: 16, time: "03:12:02.622", src: "192.168.41.22", dst: "192.168.44.87", proto: "TCP", len: 60, info: "502 → 50320 [SYN, ACK] Seq=0 Ack=1 Win=4096 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.41.22, Dst: 192.168.44.87", "Transmission Control Protocol, Src Port: 502, Dst Port: 50320, Flags: 0x012 (SYN, ACK)"] },
          { no: 17, time: "03:12:02.623", src: "192.168.44.87", dst: "192.168.41.22", proto: "TCP", len: 60, info: "50320 → 502 [ACK] Seq=1 Ack=1 Win=8192 Len=0", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.22", "Transmission Control Protocol, Src Port: 50320, Dst Port: 502, Flags: 0x010 (ACK)"] },
          { no: 18, time: "03:12:02.640", src: "192.168.44.87", dst: "192.168.41.22", proto: "Modbus/TCP", len: 66, info: "Query: Trans: 1; Unit: 1, Func: 3: Read Holding Registers", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.22", "Transmission Control Protocol, Src Port: 50320, Dst Port: 502", "Modbus/TCP: Transaction Identifier: 1, Protocol Identifier: 0, Length: 6, Unit Identifier: 1", "Modbus: Function Code: Read Holding Registers (3), Reference Number: 107, Word Count: 1"], data: "00 01 00 00 00 06 01 03 00 6b 00 01" },
          { no: 19, time: "03:12:02.659", src: "192.168.41.22", dst: "192.168.44.87", proto: "Modbus/TCP", len: 65, info: "Response: Trans: 1; Unit: 1, Func: 3: Read Holding Registers", tree: ["Internet Protocol Version 4, Src: 192.168.41.22, Dst: 192.168.44.87", "Transmission Control Protocol, Src Port: 502, Dst Port: 50320", "Modbus/TCP: Transaction Identifier: 1, Protocol Identifier: 0, Length: 5, Unit Identifier: 1", "Modbus: Function Code: Read Holding Registers (3), Byte Count: 2", "Register 107 (UINT16): 400"], data: "00 01 00 00 00 05 01 03 02 01 90" },
          { no: 20, time: "03:12:09.204", src: "192.168.44.87", dst: "192.168.41.22", proto: "Modbus/TCP", len: 66, info: "Query: Trans: 2; Unit: 1, Func: 6: Write Single Register", tree: ["Internet Protocol Version 4, Src: 192.168.44.87, Dst: 192.168.41.22", "Transmission Control Protocol, Src Port: 50320, Dst Port: 502", "Modbus/TCP: Transaction Identifier: 2, Protocol Identifier: 0, Length: 6, Unit Identifier: 1", "Modbus: Function Code: Write Single Register (6), Reference Number: 107", "Register 107 (UINT16): 550"], data: "00 02 00 00 00 06 01 06 00 6b 02 26" },
          { no: 21, time: "03:12:09.226", src: "192.168.41.22", dst: "192.168.44.87", proto: "Modbus/TCP", len: 66, info: "Response: Trans: 2; Unit: 1, Func: 6: Write Single Register", tree: ["Internet Protocol Version 4, Src: 192.168.41.22, Dst: 192.168.44.87", "Transmission Control Protocol, Src Port: 502, Dst Port: 50320", "Modbus/TCP: Transaction Identifier: 2, Protocol Identifier: 0, Length: 6, Unit Identifier: 1", "Modbus: Function Code: Write Single Register (6), Reference Number: 107", "Register 107 (UINT16): 550"], data: "00 02 00 00 00 06 01 06 00 6b 02 26" },
          { no: 22, time: "03:12:10.102", src: "192.168.40.11", dst: "192.168.41.22", proto: "Modbus/TCP", len: 66, info: "Query: Trans: 1205; Unit: 1, Func: 3: Read Holding Registers", tree: ["Internet Protocol Version 4, Src: 192.168.40.11, Dst: 192.168.41.22", "Transmission Control Protocol, Src Port: 49822, Dst Port: 502", "Modbus/TCP: Transaction Identifier: 1205, Protocol Identifier: 0, Length: 6, Unit Identifier: 1", "Modbus: Function Code: Read Holding Registers (3), Reference Number: 107, Word Count: 1"], data: "04 b5 00 00 00 06 01 03 00 6b 00 01" },
          { no: 23, time: "03:12:10.120", src: "192.168.41.22", dst: "192.168.40.11", proto: "Modbus/TCP", len: 65, info: "Response: Trans: 1205; Unit: 1, Func: 3: Read Holding Registers", tree: ["Internet Protocol Version 4, Src: 192.168.41.22, Dst: 192.168.40.11", "Transmission Control Protocol, Src Port: 502, Dst Port: 49822", "Modbus/TCP: Transaction Identifier: 1205, Protocol Identifier: 0, Length: 5, Unit Identifier: 1", "Modbus: Function Code: Read Holding Registers (3), Byte Count: 2", "Register 107 (UINT16): 550"], data: "04 b5 00 00 00 05 01 03 02 02 26" },
        ],
        objectives: [
          { id: "src", task: "A burst of very short connections touched the controller range. Which IP address sent them?", hint: "[SYN]", answer: ["192.168.44.87"], why: "One source, many addresses, seconds apart, and no data sent. That's T0846 Remote System Discovery (Discovery, TA0102). No engineering job looks like this, because a real engineer already knows which controller they need." },
          { id: "count", task: "How many controller addresses did it try?", hint: "[SYN]", answer: ["6", "six"], why: "Three answered with SYN, ACK and three never did, so the sweep told the sender what's alive. The seventh SYN, packet 15, is the sender coming back to the one it chose." },
          { id: "fc", task: "One request changed the controller. What is its function code?", hint: "\"Func: 6\"", answer: ["6", "06", "0x06"], why: "Packets 18 and 20 use the same protocol, port, controller and source. Only the function code differs: 3 reads and 6 writes. Function code 16 is the multi-register version of the same act." },
          { id: "val", task: "What value was written to register 107?", hint: "\"Write Single Register\"", answer: ["550"], why: "Wire address 107 is register 40108, the gate setpoint: 40.0% became 55.0%. Packet 21 echoes the request, which is how Modbus says a write was accepted. Nothing in those bytes carries a username or a password. Bytes 02 26 are 550 in hexadecimal." },
          { id: "seen", task: "What value did the operator's screen read straight after? (the HMI's next poll)", hint: "ip.addr==192.168.40.11", answer: ["550"], why: "The HMI saw the truth one poll later, and that's why the night operator could put it back. Stuxnet shows it doesn't have to go that way: there, the view was faked." },
        ],
      },
      {
        kind: "deduce",
        title: "Who Moved the Gate?",
        prompt: "Six hosts talked Modbus to plc-gate-02 this week, all on the same port. One of them is the intruder. Read Tariq's notes one at a time and strike out the rest.",
        nameColumn: "Host",
        columns: ["Zone", "What it sent", "Modbus history (30 days)", "Change ticket", "When"],
        suspects: [
          { id: "hmi", name: "FS-HMI-01", cells: ["Engineering", "FC 3, read", "Every day", "Not needed", "All week"] },
          { id: "hist", name: "FS-HIST-01", cells: ["Site operations", "FC 3, read", "Every day", "Not needed", "All week"] },
          { id: "eng1", name: "FS-ENG-01", cells: ["Engineering", "FC 6, write", "Monthly", "CHG-2291, calibration", "Tue 10:20, in the window"] },
          { id: "eng2", name: "FS-ENG-02", cells: ["Engineering", "FC 6, write", "Monthly", "None on file", "Weekend, no window"] },
          { id: "vend", name: "FS-VEND-02", cells: ["Vendor VLAN", "FC 6, write", "None", "CHG-2304, escorted", "Mon 11:05, in the window"] },
          { id: "comm", name: "FS-COMM-07", cells: ["Vendor VLAN", "FC 6, write", "None", "None on file", "Weekend, no window"] },
        ],
        clues: [
          "The gate moved, so this host changed a value. It did not just read one.",
          "Nobody planned this: the change log has no ticket for it.",
          "The sensor has no earlier Modbus record of this source talking to the controller.",
        ],
        culprit: "comm",
        why: "FS-COMM-07, the 192.168.44.87 in your capture, sits outside the engineering block, has no Modbus history, and wrote with no ticket. It's a commissioning laptop left on the old vendor VLAN in the spring. The write itself is Unauthorized Message: Command Message. FS-HMI-01 and FS-HIST-01 only read, and that's invisible noise. FS-ENG-01 is routine however many writes it sends: right station, ticket, window, so check the change log. That write really happened and is authorised, so it closes as a Benign True Positive citing CHG-2291. It is not a False Positive, because the rule did not misfire. FS-VEND-02 had no history either, but it had a ticket and an escort. FS-ENG-02 is a loose end: a known station with no paperwork is a call to the engineer, not an incident yet. Same port, same controller, opposite verdicts.",
      },
    ],
    // ── Reading 6: watching what can't run an agent ──
    "ot-r6": [
      {
        kind: "simulate",
        title: "How Do You Watch a Controller?",
        prompt: "IT asked why there's no EDR on plc-gate-02. Tariq asks you to try each option against the plant's three tests. Run all five and see what each one costs.",
        checks: [
          { name: "Visibility", question: "Does it see the Modbus traffic to the controller?" },
          { name: "Control loop", question: "Is the loop left alone, with no added delay and no new point of failure?" },
          { name: "Certification", question: "Do the vendor's support and the safety certification stay valid?" },
        ],
        scenarios: [
          { id: "agent", label: "EDR agent on the PLC", detail: "Install a third-party security agent on plc-gate-02.", results: ["fail", "fail", "fail"], why: ["It can't run. A PLC has a minimal, vendor-proprietary real-time OS with barely enough CPU and memory for its own logic.", "Anything competing for those cycles competes with the control program.", "Unapproved software can void support and invalidate a certification granted for one exact configuration."], verdict: "Almost nothing at Level 0 or 1 can run an agent. That's structural, not a budget problem." },
          { id: "inline", label: "Inline IPS on the cable", detail: "Put a blocking appliance on the link between the switch and plc-gate-02.", results: ["pass", "fail", "pass"], why: ["It sees every packet.", "It adds latency and a single point of failure to a safety-critical loop. A bad signature could stop the gate's traffic.", "The controller itself isn't touched."], verdict: "Blocking belongs at the zone boundary, under change control, not on the controller's own link." },
          { id: "scan", label: "Active scanner", detail: "Sweep the controller subnet weekly with a vulnerability scanner.", results: ["fail", "fail", "pass"], why: ["It builds an inventory, but it doesn't watch live traffic.", "Unexpected packets can hang an old controller. In OT, scanning a live process is a change, not a look.", "Nothing is installed."], verdict: "Keep active probing for planned outages, with operations in the room." },
          { id: "span", label: "SPAN port", detail: "Switched Port Analyzer: the control switch mirrors traffic to FS-SENSOR-01.", results: ["pass", "pass", "pass"], why: ["The switch duplicates traffic to a monitoring port. A busy switch may drop copies, so check for gaps.", "The sensor reads a copy, so it sits outside the loop.", "Nothing changes on the controller."], verdict: "Passive: it sees everything and changes nothing. That also means it can't stop anything, and it can't reset a session." },
          { id: "tap", label: "Network TAP", detail: "A Test Access Point: hardware on the cable that copies every bit.", results: ["pass", "pass", "pass"], why: ["It copies every bit without relying on the switch.", "The original signal path isn't touched once fitted. Fitting it needs a short planned break on the link.", "Nothing changes on the controller."], verdict: "Also passive. TAP or SPAN, a sensor gives you detection only, so the response has to come from somewhere else." },
        ],
      },
      {
        kind: "inspect",
        title: "Reading a Modbus Alert Rule",
        prompt: "Zeek writes down everything the sensor decodes. Suricata raises an alert when traffic matches a signature. Here's the rule Tariq runs for writes from the wrong place. Open each part and see what it does and where it can fail.",
        artifact: "FS-SENSOR-01 · Suricata rule and config",
        items: [
          { id: "p1", text: "alert modbus", tag: "Action and protocol", tone: "info", note: "alert only raises an alert. A sensor fed by a mirror has no path back to the wire: it can't drop a packet or inject a reset." },
          { id: "p2", text: "!$ENG_HOSTS any -> $PLC_HOSTS 502", tag: "Who to whom", tone: "info", note: "Any source except the listed engineering hosts, going to any controller. The rule is only as good as that list." },
          { id: "p3", text: "modbus: access write;", tag: "What", tone: "trust", note: "Suricata reads the function for you, so this fires on any write. A read from the same source stays quiet." },
          { id: "p4", text: "app-layer.protocols.modbus.enabled: yes", tag: "Pitfall", tone: "warn", note: "The Modbus parser is off by default in suricata.yaml. Without it the rule never fires, and the silence looks like a quiet plant." },
          { id: "p5", text: "zeek.modbus.func · zeek.modbus.values", tag: "Zeek's half", tone: "trust", note: "Zeek rebuilds each exchange as fields, alert or no alert. Suricata tells you the moment something matched. Zeek answers 'has this source ever talked to this controller?'" },
        ],
      },
    ],
    // ── Reading 7: responding without breaking the plant ──
    "ot-r7": [
      {
        kind: "hotspot",
        title: "Find the Holes in the Boundary",
        prompt: "This is FS-FW-01, the firewall at the Industrial DMZ, as it stood on Sunday. Rules are read top down. It should force IT-to-OT traffic through one logged chokepoint and let only listed engineering hosts write to controllers. Find every rule that breaks that.",
        artifact: "FS-FW-01 · IT/OT boundary policy, Modbus and remote-access rules · exported Sunday 09:40",
        finish: "Every hole is marked. Close them at the firewall, one rule at a time, with operations on the call.",
        parts: [
          { id: "f1", text: "10  permit  FS-HIST-01 > DMZ report share  tcp/445", flag: false, style: "body", note: "Fine. The historian sends reports up through the DMZ, so that path crosses the chokepoint." },
          { id: "f2", text: "20  permit  10.8.0.0/16 > FS-JUMP-01  tcp/3389  log", flag: false, style: "body", note: "Fine. This is the chokepoint doing its job: one host, logged." },
          { id: "f3", text: "30  permit  10.8.0.0/16 > 192.168.41.0/24  tcp/502", flag: true, style: "body", note: "The whole corporate range straight to the controllers. It skips Level 3.5 and exposes a protocol that can't check who's asking." },
          { id: "f4", text: "40  permit  FS-JUMP-01 > FS-ENG-01  tcp/3389  log", flag: false, style: "body", note: "Fine. It's the approved route from the Purdue walk." },
          { id: "f5", text: "50  permit  FS-JUMP-01 > 192.168.44.87  tcp/3389  # temp, vendor job, spring", flag: true, style: "body", note: "A temporary rule nobody removed. It gives a remote session into the old vendor VLAN, and that VLAN can reach the controllers." },
          { id: "f6", text: "60  permit  FS-HIST-01 > 192.168.41.0/24  modbus read", flag: false, style: "body", note: "Fine. The historian only needs to read." },
          { id: "f10", text: "65  permit  FS-HMI-01 > 192.168.41.0/24  modbus read", flag: false, style: "body", note: "Fine. The operator screens poll the controllers, and that's all this rule lets them do." },
          { id: "f7", text: "70  permit  FS-ENG-01, FS-ENG-02 > 192.168.41.0/24  modbus write", flag: false, style: "body", note: "This is command allowlisting: only listed sources may send write function codes. Even someone who reaches the segment shouldn't get a write forwarded." },
          { id: "f8", text: "80  permit  192.168.0.0/16 > 192.168.41.0/24  tcp/502", flag: true, style: "body", note: "Any plant address may read and write, which undoes rule 70. A broad rule under a tight one is how allowlists quietly stop working." },
          { id: "f9", text: "90  deny  any > any  log", flag: false, style: "body", note: "Fine. It's the default deny, and it's logged." },
        ],
      },
      {
        kind: "outbreak",
        title: "Cut Ahead of the Spread",
        prompt: "Tariq's drill before any real call. An intruder is hopping between Windows hosts at Levels 2 and 3. There are no PLCs in this map and no agents, so isolating a host means a technician shutting its switch port, and each port you shut takes a screen or a data feed from the operators. Cut clean hosts ahead of the spread, where one cut protects the most, and keep it off the safety engineering station.",
        hostPrefix: "FS-OPS",
        cols: 6,
        rows: 5,
        crown: "SIS-ENG",
        via: "RDP with a stolen maintenance account",
        lesson: "Cutting late loses the hosts behind the cut. Cutting ahead, where the network narrows, saves the most, and on a plant that narrow place is the Level 3.5 boundary. But this drill only counted hosts, and a plant counts consequences. The safety engineering station mattered most, as TRITON showed. Shut the port of an HMI and the operators lose sight of a running process. Shut a historian's port and regulatory records stop. So before you cut, ask what that host is keeping running right now.",
      },
      {
        kind: "intercept",
        title: "Approve the Cut, or Stop It",
        prompt: "Sunday, 10:00. Corporate IT's incident lead is sending response actions to the plant, one after another, and the turbine is at 80% load. Tariq has given you the pen. Approve what's safe and stop what would hurt the process.",
        protect: "the plant",
        blockLabel: "Stop it",
        passLabel: "Approve",
        seconds: 12,
        items: [
          { id: "c1", text: "Push an EDR isolate action to plc-gate-02", sub: "From the corporate console", bad: true, why: "No agent runs on a PLC, so there's nothing to receive it. Containment here happens in the network." },
          { id: "c2", text: "Shut the switch port of FS-COMM-07", sub: "A laptop with no process role, shift operator agrees", bad: false, why: "It's the source, it drives nothing, and operations has confirmed that. That's the cut you want." },
          { id: "c3", text: "Restart plc-turb-01 to clear anything bad", sub: "Turbine running at 80% load", bad: true, why: "A reboot under load can trip the process, and it destroys volatile evidence you can't get back." },
          { id: "c4", text: "Drop all Modbus traffic on every plant switch", sub: "Just until we know more", bad: true, why: "It also cuts FS-HMI-01's polling, so operators lose the numbers they're running the plant on. Any wide block has to be agreed with operations first." },
          { id: "c5", text: "Remove firewall rule 50, the old jump path", sub: "Operations checked: nothing uses it", bad: false, why: "It removes the intruder's route at the boundary, and it can be undone." },
          { id: "c6", text: "Shut the switch port of FS-HMI-01", sub: "No agent on it, and it talks to the controller", bad: true, why: "It talks to the controller because that's its job. Isolate it and the control room is blind to a running turbine." },
          { id: "c7", text: "Ask the gate's process engineer what register 40108 should read", sub: "They set it back, nobody else", bad: false, why: "A write that landed may have changed something the process depends on. Only the people who know the right values can say what's wrong and put it back safely." },
          { id: "c8", text: "Run a vulnerability scan of the controller subnet", sub: "To see what else is exposed", bad: true, why: "Unexpected packets can hang old controllers. It would also bury the evidence in your own traffic." },
          { id: "c9", text: "Copy the sensor's capture and Zeek records to the case", sub: "A read-only copy", bad: false, why: "The sensor is passive, so this costs the plant nothing. It's your only record, since the controllers have no logs to give you." },
          { id: "c10", text: "Bypass sis-turb-01 so the turbine can't trip mid-investigation", sub: "Less noise for the team", bad: true, why: "The safety system is the last line of defence. Nobody disables it for convenience, least of all during an incident." },
          { id: "c11", text: "Check the change log for Saturday's FS-ENG-02 write", sub: "Ask the engineer before acting", bad: false, why: "A known station without paperwork needs a phone call. It isn't a reason to cut the engineers off." },
        ],
        lesson: "In OT, ask before every cut: what does this host keep running, who in operations agrees, and can it be undone? Take the source away from the plant at the boundary and leave the controller alone. Don't reboot live controllers, and don't silence a protocol everywhere. Then the people who know the process check the values. For guidance, NIST SP 800-82 Revision 3 covers OT architecture, and CISA's ICS advisories are the closest thing to a CVE feed for this kit.",
      },
    ],
    // ── Boss warm-up: the whole chain ──
    "ot-q4": [
      {
        kind: "sequence",
        title: "Nine Weeks, Two Stages",
        prompt: "Tariq lays out Fellside's own case for the regulator. Put the intrusion in order, first foothold to moving water. The ICS Cyber Kill Chain has two stages: the IT intrusion first, then building and running the attack on the process.",
        items: [
          { id: "sweep", text: "Short connections hit six controller addresses on port 502 in three seconds", note: "T0846 Remote System Discovery (Discovery, TA0102). It comes before the write, because this is how the intruder learns what answers." },
          { id: "phish", text: "A mail to an engineer lands on FS-PC-117 and the intruder has a foothold in corporate IT", note: "Stage 1, the IT intrusion. Nothing about it is industrial yet." },
          { id: "gate", text: "The intake gate moves from 40% to 55% with nobody at the panel", note: "T0831 Manipulation of Control (Impact, TA0105). The physical effect, recorded separately from the message that caused it." },
          { id: "jump", text: "An RDP session with a maintenance account opens from FS-PC-117 onto FS-JUMP-01", note: "T0886 Remote Services (Lateral Movement, TA0109). It isn't T0883, because no device here faces the internet: the session starts inside IT." },
          { id: "write", text: "A Write Single Register reaches plc-gate-02 from FS-COMM-07", note: "Stage 2, the attack itself. Unauthorized Message: Command Message, Impair Process Control (TA0106). The controller obeyed, because Modbus/TCP has no way to ask who's sending." },
          { id: "read", text: "For weeks the intruder reads network diagrams and vendor manuals on the file share", note: "Still Stage 1, and the slow part. That's the long game: the documents say what's worth touching." },
          { id: "check", text: "One read of the gate's setpoint register, to confirm it matches the manual", note: "Stage 2 opens with developing and validating the attack. Most of that happens out of sight. This is the small piece that shows on the wire." },
          { id: "comm", text: "A second RDP session crosses from FS-JUMP-01 to FS-COMM-07 on the old vendor VLAN", note: "T0886 again. This hop puts the intruder on a host that can reach the controllers, through a rule nobody removed." },
        ],
        order: ["phish", "read", "jump", "comm", "sweep", "check", "write", "gate"],
        doneNote: "Stage 1 took nine weeks and Stage 2 took under a minute on the wire. Crossing, sweep, write, effect: every step used a normal session or a normal protocol, and no protocol along the way asked who was sending. Only the boundary, an allowlist and a watching sensor could have caught it.",
      },
    ],
  },
};
