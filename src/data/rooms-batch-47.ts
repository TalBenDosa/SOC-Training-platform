/**
 * Learning Rooms -- Batch 47
 *
 * Closes a P2 coverage gap (topic 7 of 9): OT/ICS Security for SOC Analysts.
 * The platform already ships a hands-on OT investigation scenario
 * (ot-network-anomaly, an IT-to-OT Modbus intrusion investigated purely
 * through Zeek and Suricata telemetry -- see
 * src/lib/sim/scenario-packs/otNetworkAnomaly.ts) but had ZERO standalone
 * theory content teaching the vocabulary, architecture, or real incidents
 * that scenario assumes a student already knows. This room is that missing
 * theory, paired with a fresh log_analysis/analyst_choice pair distinct from
 * (but narratively consistent with) the shipped scenario's Modbus write
 * pattern.
 *
 * Rooms in this batch:
 *  1. ot-ics-security
 *
 * TECHNIQUES COVERED, verified directly against attack.mitre.org/matrices/ics/
 * and each technique's own page at write time (2026-09-09):
 *   - T0846 -- Remote System Discovery, Discovery (TA0102). Sub-techniques
 *     named: T0846.001 (Port Scan), T0846.003 (Multicast Discovery).
 *   - T0855 -- Unauthorized Command Message, Impair Process Control (TA0106).
 *   - T0886 -- Remote Services. Verified to carry BOTH Initial Access
 *     (TA0108) AND Lateral Movement (TA0109) -- listed with both tactics
 *     throughout this room's readings, never just one.
 *   - T0812 -- Default Credentials, Initial Access (TA0108).
 *   - T0836 -- Modify Parameter, Impair Process Control (TA0106). MITRE's own
 *     documented example is Stuxnet (frequency-converter-drive reprogramming
 *     at Natanz).
 *   - T0831 -- Manipulation of Control, Impact (TA0105). MITRE's own
 *     documented example is Industroyer (breaker toggling).
 *   - T0883 -- Internet Accessible Device, Initial Access (TA0108). MITRE's
 *     own documented example is the Bowman Avenue Dam incident.
 *
 * REAL INCIDENTS covered, with the technique(s) each maps to:
 *   - Stuxnet (2010) -> T0836
 *   - TRITON / TRISIS / HatMan (2017, Saudi petrochemical SIS) -> T0886
 *   - Industroyer / CRASHOVERRIDE (17 Dec 2016, Kyiv substation) -> T0855, T0831
 *   - Oldsmar, FL water treatment facility (5 Feb 2021) -> T0883, T0886
 *     (CISA/FBI/EPA/MS-ISAC advisory AA21-042A). The reading covering this
 *     incident explicitly flags later reporting that raised doubts about
 *     whether it was a confirmed intrusion versus human error -- taught as a
 *     professional sourcing-hygiene lesson, not as fact-softening.
 *
 * The room's own log_analysis/analyst_choice pair is a FRESH scenario (a
 * fictional municipal utility, Meridian Valley Water Authority, plc-dose-03/
 * 04, 172.20.5.0/24 OT range) -- deliberately distinct from the shipped
 * ot-network-anomaly scenario's plc-line1-01/172.16.30.0/24 story, so the two
 * pieces of content teach the same discriminators (source identity + Modbus
 * function code) without being literally duplicated. Field names for both
 * Corelight (Zeek) and Suricata events match src/lib/sim/scenario-packs/
 * otNetworkAnomaly.ts exactly (corelight.modbus / corelight.conn dataset
 * values, zeek.conn and zeek.modbus prefixed fields, and Suricata's alert
 * and rule / host.name common-field shape), all of which are registered in
 * scripts/log-field-registry.json (corelight-zeek prefixes "corelight."/
 * "zeek."; suricata exactFields; commonFields for event.dataset, event.module,
 * host.name, rule.description/level/groups, message, action_result).
 * source:"ids" and event_type:"net_connection"/"ids_signature" both match the
 * LogSource/EventType unions in src/lib/sim/types.ts. edr_scope:"non_edr" on
 * both events -- there is no EDR sensor on this segment, so no hashDatabase
 * dependency applies. it_verify_result/it_verify_message (never a raw field)
 * is the sanctioned FP-resolution mechanism for the analyst_choice control
 * case, exactly as used elsewhere in this platform's authored rooms.
 *
 * SOURCES consulted directly for this content:
 *  - MITRE ATT&CK for ICS matrix (attack.mitre.org/matrices/ics/)
 *  - MITRE ATT&CK for ICS, T0846 Remote System Discovery
 *    (attack.mitre.org/techniques/T0846/)
 *  - MITRE ATT&CK for ICS, T0855 Unauthorized Command Message
 *    (attack.mitre.org/techniques/T0855/)
 *  - MITRE ATT&CK for ICS, T0886 Remote Services
 *    (attack.mitre.org/techniques/T0886/)
 *  - MITRE ATT&CK for ICS, T0836 Modify Parameter
 *    (attack.mitre.org/techniques/T0836/)
 *  - MITRE ATT&CK for ICS, T0831 Manipulation of Control
 *    (attack.mitre.org/techniques/T0831/)
 *  - MITRE ATT&CK for ICS, T0883 Internet Accessible Device
 *    (attack.mitre.org/techniques/T0883/)
 *  - MITRE ATT&CK for ICS, T0812 Default Credentials
 *    (attack.mitre.org/techniques/T0812/)
 *  - NIST SP 800-82 Revision 3, Guide to Operational Technology (OT) Security
 *    (csrc.nist.gov/pubs/sp/800/82/r3/final)
 *  - CISA/FBI/EPA/MS-ISAC Joint Advisory AA21-042A, Compromise of U.S. Water
 *    Treatment Facility (cisa.gov/news-events/cybersecurity-advisories/aa21-042a)
 *  - CISA ICS Advisories (cisa.gov/news-events/ics-advisories)
 */


const otIcsSecurityRoom = {
  "id": "ot-ics-security",
  "title": "OT/ICS Security for SOC Analysts: Investigating the Plant Floor",
  "description": "SCADA, PLCs, HMIs, and industrial protocols look nothing like the Windows Event Logs, EDR telemetry, and cloud audit trails this platform's other rooms are built on -- and this room exists because a whole generation of SOC analysts reaches this platform's OT investigation scenario with zero background in what any of that vocabulary means. Follow Meridian Valley Water Authority's water treatment plant from the ground up: what a PLC, HMI, RTU, DCS, and SCADA architecture actually are and where each sits in the Purdue Model; why Modbus, DNP3, S7comm, and EtherNet/IP were built with no authentication at all, and what that means the moment IT and OT networks converge; four real, publicly documented incidents -- Stuxnet, TRITON/TRISIS, Industroyer/CRASHOVERRIDE, and Oldsmar -- mapped to their actual MITRE ATT&CK for ICS technique IDs; how to read genuine Zeek and Suricata telemetry for an unauthorized Modbus write; and why OT detection and response cannot look like a Windows workstation's, because you cannot install an agent on a programmable logic controller.",
  "difficulty": "intermediate",
  "category": "OT/ICS Security",
  "estimatedMinutes": 75,
  "xp": 240,
  "icon": "🏭",
  "prerequisites": [
    "networking-fundamentals",
    "networking-protocols",
    "firewall-network-security",
    "mitre-attack"
  ],
  "tasks": [
    {
      "type": "reading" as const,
      "id": "ot-r0",
      "heading": "Welcome to the Plant Floor: Why OT Security Is a Different Discipline",
      "content": "Every skill this platform has taught so far -- reading Windows Event Logs, pivoting through EDR process trees, correlating cloud audit logs -- assumes one thing that is completely absent on a factory floor, in a water treatment plant, or inside a power substation: an agent running on the endpoint, phoning home with rich telemetry. This room is about the environment where that assumption breaks entirely.\n\nOT (Operational Technology) is hardware and software that directly senses and controls PHYSICAL equipment -- a valve, a pump, a circuit breaker, a conveyor belt -- rather than storing and moving information the way IT (Information Technology) does. ICS (Industrial Control System) is the umbrella term for the automation built on top of OT that runs an industrial process end to end: a power grid, a refinery, a municipal water system, a factory line. This room follows a single fictional but realistic case at Meridian Valley Water Authority, a municipal utility running a treatment plant (Meridian Water Treatment Plant 3) whose chemical-dosing controllers sit on an isolated production VLAN -- to make every concept concrete rather than abstract.\n\n### Why This Room Exists\n\nThis platform already has a hands-on OT investigation scenario -- an IT-to-OT network intrusion investigated purely through Zeek and Suricata telemetry -- that many students reach with zero background in what a PLC even is, what Modbus does, or why the investigation has no EDR to fall back on. This room is the missing theory: the vocabulary, the architecture, the real incidents, and the detection philosophy that scenario, and any real OT investigation, assumes you already know.\n\n### The One Priority Inversion That Explains Everything Else\n\nIT security training centers on the CIA triad: Confidentiality, Integrity, Availability, usually in that order. OT inverts it -- often written **AIC** instead. **Availability** comes first: a water treatment plant cannot simply reboot a dosing controller mid-shift the way an IT team reboots a web server, because unplanned downtime of a physical process can have physical, sometimes life-safety, consequences that a data breach does not. **Integrity** is second -- does a sensor reading or an actuator command reflect what is actually happening in the physical world. **Confidentiality** is a distant third: almost nobody at Meridian Valley Water Authority worries about an outsider reading a flow-rate value; everybody worries about someone changing one.\n\nThat single inversion is the reason nearly everything in this room will look unfamiliar coming from an IT background: control systems run operating systems well over a decade old because a device's safety certification and vendor support contract are tied to one exact, tested software configuration; some systems only get patched once a year, during a single planned outage window; and, as this room's later readings cover in direct, practical terms, you generally cannot install an antivirus agent, an EDR sensor, or even a simple logging agent on the controllers themselves at all.\n\nBy the end of this room you will be able to define every OT/ICS term this platform's scenario content assumes, place a real asset at its correct level in the Purdue Model, name the real, publicly documented incidents that anchor this entire field, read genuine Zeek and Suricata telemetry for an OT intrusion, and reason correctly about detection and response in an environment where none of your IT-side tools apply directly.",
      "checkpoint": {
        "question": "Per this reading, what is the practical reason OT security inverts the IT CIA triad's usual priority order, often written AIC instead?",
        "options": [
          "Because Confidentiality is technically impossible to achieve on any industrial network, so it is removed from consideration entirely",
          "Because unplanned downtime or a manipulated physical process can have physical, sometimes life-safety, consequences that a typical data breach does not -- so Availability and Integrity are prioritized ahead of Confidentiality",
          "Because OT devices are incapable of storing any confidential information, making Confidentiality an irrelevant concept in this domain",
          "Because every OT regulation legally forbids organizations from prioritizing Confidentiality under any circumstances"
        ],
        "answer": 1,
        "explanation": "This reading states the reason directly: unplanned downtime and manipulated physical processes carry physical, sometimes life-safety, consequences a data breach does not, which is why Availability and Integrity outrank Confidentiality in OT. Confidentiality is not impossible in OT (option a) -- it is simply a lower priority, not an impossibility. OT devices absolutely can hold sensitive configuration and process data (option c is false). No blanket legal prohibition on prioritizing Confidentiality exists (option d is invented)."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "ot-r1",
      "heading": "The Device Zoo and the Purdue Model: SCADA, PLC, HMI, RTU, DCS",
      "content": "Before any telemetry in this room will make sense, every one of these terms needs a plain, from-zero definition -- almost none of this vocabulary appears anywhere else in this platform's curriculum.\n\n**PLC (Programmable Logic Controller):** a small, ruggedized industrial computer that runs one fixed control program in a continuous loop -- read sensor inputs, execute logic, write outputs -- dozens of times per second, indefinitely. At Meridian Water Treatment Plant 3, `plc-dose-03` and `plc-dose-04` are the two PLCs that control chemical-dosing pump speed on Lines 3 and 4.\n\n**RTU (Remote Terminal Unit):** functionally similar to a PLC, but built for the field -- long-distance telemetry over low-bandwidth or serial links, common on pipelines, remote wellheads, and substations spread across a wide area.\n\n**DCS (Distributed Control System):** the PLC concept scaled up to an entire facility -- many controllers under one unified configuration philosophy, typical of refineries and large continuous-process plants.\n\n**HMI (Human-Machine Interface):** the screen an operator actually watches -- almost always a Windows PC running vendor software that visualizes live values from the controllers and lets an authorized human issue commands. Meridian's control room runs its HMI software from `ENG-WS-02`, the plant's sole authorized engineering workstation for Lines 3 and 4.\n\n**SCADA (Supervisory Control and Data Acquisition)** is not a device -- it is an architecture. SCADA is the overall system of HMIs, servers, and communication links that let a small control-room team supervise PLCs and RTUs spread across a wide area from one place.\n\n### The Purdue Model: Where Every Asset Sits\n\nThe Purdue Model (the Purdue Enterprise Reference Architecture) is the reference diagram nearly every OT security standard builds on, including NIST Special Publication 800-82 Revision 3.\n\n| Level | Name | What Lives Here | Meridian Example |\n| --- | --- | --- | --- |\n| 5 | Enterprise Network | Corporate email, internet access | Meridian Valley Water Authority's corporate LAN |\n| 4 | Business Planning & Logistics | ERP, billing, scheduling | The utility's customer billing system |\n| 3.5 | Industrial DMZ | Firewalled buffer zone | The firewall pair separating the plant network from the corporate WAN |\n| 3 | Site Operations | MES, historian databases | Meridian's process historian, logging every dosing rate for regulatory reporting |\n| 2 | Area Supervisory Control | HMI, SCADA servers | `ENG-WS-02`, the plant's engineering/HMI workstation |\n| 1 | Basic Control | PLCs, RTUs, DCS controllers | `plc-dose-03` and `plc-dose-04` |\n| 0 | Physical Process | Sensors, actuators, pumps | The physical dosing pumps and flow sensors on Lines 3 and 4 |\n\nLevel 3.5 was not part of the original 1990s Purdue diagram, but modern OT security treats it as essential: every hop of traffic between the OT zone (Levels 0-3) and the IT zone (Levels 4-5) is expected to cross this controlled, logged chokepoint rather than connecting directly. Every real intrusion this room covers later is, at its core, a story of that exact boundary being crossed without going through the chokepoint at all.",
      "checkpoint": {
        "question": "Per this reading's Purdue Model table, at which level does ENG-WS-02, Meridian's HMI/engineering workstation, sit -- and what kind of asset shares that level with it?",
        "options": [
          "Level 0 (Physical Process), alongside the plant's sensors and actuators",
          "Level 2 (Area Supervisory Control), alongside other HMI and SCADA server assets",
          "Level 4 (Business Planning & Logistics), alongside the utility's ERP and billing systems",
          "Level 3.5 (Industrial DMZ), alongside the firewall pair separating OT from corporate IT"
        ],
        "answer": 1,
        "explanation": "The table places ENG-WS-02 at Level 2 (Area Supervisory Control), the level for HMI screens and SCADA servers overseeing a plant area -- exactly where an engineering/HMI workstation belongs. Level 0 (option a) holds physical sensors and actuators, not workstations. Level 4 (option c) holds business systems like ERP and billing, not plant-floor HMIs. Level 3.5 (option d) is the DMZ firewall boundary itself, not a workstation."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "ot-r2",
      "heading": "Protocols With No Front Door: Modbus, DNP3, S7comm, EtherNet/IP",
      "content": "Every protocol Meridian's plant floor speaks shares one structural fact that explains nearly every OT intrusion this room will cover: none of them were designed with authentication.\n\n| Protocol | Port | Typical Use | Origin |\n| --- | --- | --- | --- |\n| `Modbus/TCP` | `502/TCP` | The most widely deployed industrial protocol -- what plc-dose-03 and plc-dose-04 both speak | Originally Modicon, now an open standard |\n| `DNP3` (Distributed Network Protocol) | `20000/TCP` | Power grid and water/wastewater utility telemetry between RTUs and a SCADA master | Utility-sector standard |\n| `S7comm` | `102/TCP` | Siemens SIMATIC S7-series PLC programming traffic | Siemens-proprietary |\n| `EtherNet/IP` (built on CIP) | `44818/TCP`, `2222/UDP` | Discrete manufacturing and factory automation | Rockwell Automation / ODVA |\n\n### Why \"No Authentication\" Is Not an Oversight\n\nThese protocols were designed decades ago for closed, physically isolated serial networks where the only devices that could ever reach the wire were already inside a locked control room. `Modbus/TCP` has no username, no password, and no encryption: any host that can route a TCP packet to port `502` can read or write coils and registers with the exact same authority as `ENG-WS-02`, Meridian's own engineering workstation. `DNP3`, `S7comm`, and `EtherNet/IP` share the identical gap.\n\nFunction codes matter more than the protocol name. Modbus function code `3` or `4` requests a **read** -- harmless, an HMI display simply refreshing a number. Function code `6` (Write Single Register) or `16` (Write Multiple Registers) requests a **write** -- an instruction that changes what the physical process actually does, such as the dosing-pump speed registers on `plc-dose-03`. Two sessions on the identical protocol, port, and controller can carry opposite consequences, and the only way to tell them apart on the wire is the function code and the identity of the source -- never a credential, because none exists.\n\n### How the Isolation Assumption Broke\n\nAir-gapping -- physically disconnecting OT from anything else -- was the historical answer to this authentication gap. That isolation has eroded: Meridian's own process historian at Level 3 pulls dosing data up toward Level 4 for regulatory reporting, the dosing-pump vendor expects remote access for warranty-covered support, and engineers occasionally carry laptops between the corporate network and the plant floor in the same week. MITRE ATT&CK for ICS names three techniques for exactly how this exposure gets exploited: `T0883`, Internet Accessible Device (Initial Access, TA0108) -- an ICS asset reachable directly from the internet through a weakly protected remote-access function, the exact pattern behind the real Bowman Avenue Dam incident MITRE cites, where a small dam's control system was reached through a cellular modem secured only by a brute-forceable password; `T0812`, Default Credentials (Initial Access) -- vendor-set usernames and passwords, often published in a public instruction manual, that many organizations never change; and `T0886`, Remote Services, which MITRE places under **both** Initial Access (TA0108) **and** Lateral Movement (TA0109), because the identical mechanism -- an RDP session, an SSH connection, an exposed engineering protocol -- can be an attacker's very first way in, or the exact pivot they use once already inside the IT network.",
      "checkpoint": {
        "question": "Per this reading, why does MITRE ATT&CK for ICS list T0886 (Remote Services) under two different tactics -- both Initial Access (TA0108) and Lateral Movement (TA0109)?",
        "options": [
          "Because ATT&CK for ICS has a data-entry error that this reading is documenting as a known mistake in the framework",
          "Because the identical mechanism (an RDP session, an SSH connection, an exposed engineering protocol) can be an attacker's very first way into an environment, or the exact pivot point used once already inside the IT network -- so the same technique legitimately serves both roles",
          "Because Remote Services only ever counts as Initial Access, and the Lateral Movement listing applies exclusively to a completely unrelated technique with a similar name",
          "Because every single technique in MITRE ATT&CK for ICS is listed under both of these two tactics as a matter of framework-wide policy"
        ],
        "answer": 1,
        "explanation": "This reading explains the dual listing directly: the same remote-access mechanism can be the attacker's first foothold OR the pivot used once already inside the IT network, so MITRE legitimately documents it under both tactics. This is not a data-entry error (option a) -- it is a deliberate, accurate reflection of how the technique is actually used in practice. Option c invents a nonexistent separate technique. Option d is false; this reading does not claim every ICS technique carries both tactics -- T0836 and T0855, covered later in this room, carry only one tactic each (Impair Process Control)."
      },
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "ot-q1",
      "question": "Meridian's process historian sits at Purdue Level 3, and plc-dose-03 sits at Level 1, communicating over Modbus/TCP. Which of the following correctly identifies the port Modbus/TCP uses, and the security property that traffic on that port lacks by design?",
      "options": [
        "Port 502/TCP, and Modbus/TCP has no built-in authentication, encryption, or identity mechanism at all -- any host that reaches that port can issue the same read or write function codes as the plant's own engineering workstation",
        "Port 20000/TCP, and Modbus/TCP requires a signed certificate for every write function code, which is why DNP3 is considered less secure",
        "Port 102/TCP, and Modbus/TCP encrypts every session by default, though the encryption key is published in the device's manual",
        "Port 44818/TCP, and Modbus/TCP is exclusively used for read-only telemetry, so no write function code exists in the protocol at all"
      ],
      "answer": 0,
      "explanation": "Modbus/TCP uses port 502, and this room's protocol reading states plainly that it has no authentication, encryption, or identity mechanism at all -- source identity and function code are the only usable signals. Option b confuses the port with DNP3's port (20000) and invents a certificate requirement that does not exist. Option c confuses the port with S7comm's port (102) and invents default encryption Modbus/TCP does not have. Option d confuses the port with EtherNet/IP's port (44818) and is factually wrong that Modbus has no write function code -- function codes 6 and 16 are exactly the write codes this room's reading names.",
      "xp": 20
    },
    {
      "type": "matching" as const,
      "id": "ot-m1",
      "heading": "Match Each Industrial Protocol to Its Port and Real-World Use",
      "instructions": "Match each industrial protocol Meridian's plant floor could plausibly run to the port and description this room's protocol reading gives it.",
      "pairs": [
        {
          "id": "p1",
          "left": "Modbus/TCP",
          "right": "Port 502/TCP -- no built-in authentication; function code 3/4 reads, 6/16 writes"
        },
        {
          "id": "p2",
          "left": "DNP3 (Distributed Network Protocol)",
          "right": "Port 20000/TCP -- power grid and water/wastewater utility telemetry between RTUs and a SCADA master"
        },
        {
          "id": "p3",
          "left": "S7comm",
          "right": "Port 102/TCP -- Siemens S7-series PLC engineering and programming protocol"
        },
        {
          "id": "p4",
          "left": "EtherNet/IP (built on CIP)",
          "right": "Port 44818/TCP (plus UDP 2222) -- Rockwell/Allen-Bradley industrial Ethernet, no authentication or encryption by design"
        }
      ],
      "explanation": "Each pairing matches this room's protocol reading exactly: Modbus/TCP on port 502, with function codes 3/4 for reads and 6/16 for writes; DNP3 on port 20000, the utility-sector standard for RTU-to-SCADA-master telemetry; S7comm on port 102, Siemens' own PLC engineering protocol; and EtherNet/IP on port 44818 (plus UDP 2222), Rockwell's industrial Ethernet built on the Common Industrial Protocol (CIP). All four share the same design gap this room emphasizes repeatedly: none of them authenticate who is sending a command.",
      "xp": 25
    },
    {
      "type": "reading" as const,
      "id": "ot-r3",
      "heading": "Stuxnet and TRITON/TRISIS: When Malware Targets Physical Processes and Safety Systems",
      "content": "### Stuxnet (Discovered 2010) -- T0836, Modify Parameter\n\nStuxnet targeted Siemens S7-300 series PLCs controlling uranium-enrichment centrifuges at Iran's Natanz facility. Its most consequential payload sent network bursts over the plant's Profibus network containing instructions for frequency converter drives, changing the maximum operating frequency -- the motor speed -- of the connected centrifuges outside safe bounds, while simultaneously feeding the HMI falsified sensor readings so operators saw nothing wrong. MITRE ATT&CK for ICS names Stuxnet directly as its documented example of `T0836`, Modify Parameter (Impair Process Control, TA0106): altering a value the physical process depends on to a dangerous, out-of-bounds setting -- precisely the register-write pattern this room's own log_analysis task later asks you to recognize on `plc-dose-03`.\n\n### TRITON / TRISIS / HatMan (2017) -- T0886, Remote Services\n\nIn 2017, malware known by three names -- TRITON (Mandiant), TRISIS (Dragos), HatMan (CISA/ICS-CERT) -- was deployed against a Saudi Arabian petrochemical plant's Triconex Safety Instrumented System, built by Schneider Electric. A Safety Instrumented System (SIS) is the last line of defense in an industrial plant: dedicated hardware whose only job is shutting the process down safely if something goes catastrophically wrong -- the OT equivalent of a pressure-relief valve or a circuit breaker's trip mechanism, except built entirely from control logic. MITRE ATT&CK's own documentation of this campaign states that the threat actor TEMP.Veles moved laterally through the target's IT and OT networks using RDP jump boxes and a poorly configured OT firewall -- a textbook `T0886`, Remote Services case, moving from an initial foothold toward the safety controllers themselves. TRITON is widely regarded as the first ICS attack designed specifically to enable physical damage, environmental harm, or loss of life, because it targeted the ONE system built purely to prevent exactly that outcome. The intrusion was discovered only because a bug in the malware itself triggered an unplanned safety shutdown; plant engineers initially assumed a mechanical fault, not an intrusion.\n\n### Why Both of These Matter to a Working Analyst\n\nStuxnet shows what a `T0836` Modify Parameter finding actually costs when it succeeds against a live physical process. TRITON shows that OT lateral movement (`T0886`) often has a more alarming destination than the primary control system itself -- the safety system that exists purely to catch failures in everything else. An analyst who only monitors PLCs and never considers that an SIS is a separate, even higher-value target on the same network is missing exactly the asset TRITON went after.",
      "checkpoint": {
        "question": "Per this reading, what specifically made the 2017 TRITON/TRISIS/HatMan attack against the Saudi petrochemical plant unusually significant compared to a typical PLC-targeting incident like Stuxnet?",
        "options": [
          "TRITON targeted the Safety Instrumented System (SIS) itself -- the dedicated hardware whose only job is shutting the process down safely in an emergency -- making it the first ICS attack designed to enable physical damage, environmental harm, or loss of life by disabling the system built purely to prevent that outcome",
          "TRITON was the first piece of malware ever documented to run on any Windows-based engineering workstation anywhere in an industrial environment, a capability this reading states Stuxnet's own payload never possessed or attempted to use at any point during its operation",
          "TRITON exclusively targeted municipal water treatment facilities of the exact kind this room's fictional Meridian Valley Water Authority narrative uses throughout its own readings, while Stuxnet by contrast exclusively targeted electrical power grid transmission substations",
          "TRITON was discovered immediately upon its initial deployment by the plant's own built-in intrusion detection system monitoring the Triconex controllers, unlike Stuxnet, which per this reading was never detected by any defensive tool at any point"
        ],
        "answer": 0,
        "explanation": "This reading states directly that TRITON's significance was targeting the Safety Instrumented System itself -- the last line of defense -- making it the first ICS attack designed to enable physical damage, environmental harm, or loss of life. Option b is false and irrelevant; both malware families interacted with Windows-adjacent engineering systems, and this is not the distinguishing fact this reading names. Option c misstates both sectors: TRITON targeted a petrochemical plant, and Stuxnet targeted a nuclear enrichment facility, neither a water utility nor a power grid. Option d is false -- this reading states TRITON was discovered only because a bug in the malware itself triggered an unplanned safety shutdown, not because any IDS caught it."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "ot-r4",
      "heading": "Industroyer/CRASHOVERRIDE and Oldsmar: Command Injection and Weak Remote Access",
      "content": "### Industroyer / CRASHOVERRIDE (December 17, 2016) -- T0855 and T0831\n\nOn 17 December 2016, the Russian state-linked group Sandworm Team used malware researchers named Industroyer (ESET) or CRASHOVERRIDE (Dragos) against a transmission substation outside Kyiv, Ukraine, cutting power to part of the city for about an hour. The attackers reached the ICS environment through a device dual-homed on both the IT and ICS networks -- crossing the exact Level 3.5 boundary this room's second reading described, uncontrolled -- and the malware's payload modules communicated directly with substation protective relays and circuit breakers using their own native protocols. MITRE ATT&CK documents Industroyer as toggling breakers to the open state using unauthorized command messages: this is `T0855`, Unauthorized Command Message (Impair Process Control, TA0106) -- sending a command a device was never meant to accept from that source -- while the resulting breaker state change itself is separately documented under `T0831`, Manipulation of Control (Impact, TA0105): directly altering a physical process's state through a changed setpoint or issued command.\n\n### Oldsmar, Florida Water Treatment Facility (February 5, 2021)\n\nOn 5 February 2021, an operator at a small Florida water treatment facility watched their screen as someone remotely accessed the plant's SCADA software and raised the target concentration of sodium hydroxide (a caustic chemical used in small doses for water treatment, hazardous at high concentration) from 100 parts per million to 11,100 parts per million. The operator immediately reversed the change, and the facility's own automated alarm would have caught it regardless before it ever reached the water supply. The joint CISA/FBI/EPA/MS-ISAC advisory (AA21-042A) that followed cited poor password security, an outdated operating system, and probable use of remote-access desktop-sharing software as contributing weaknesses -- the real-world pattern `T0883` (Internet Accessible Device) and `T0886` (Remote Services) both describe: a control system reachable through weakly secured remote access, with no protocol-level authentication strong enough to stop whoever reached it from issuing a fully legitimate-looking command.\n\nA professional habit worth naming directly: later reporting and statements from local officials raised the possibility that human error, rather than a confirmed external intrusion, may explain some of what happened at Oldsmar. This is not a reason to distrust the CISA advisory -- it is a reminder that even a widely reported, government-advisory-confirmed 'hack' can accumulate more certainty in the public retelling than the original evidence supported, and that a careful analyst revisits a case's sourcing rather than treating an early headline as forever settled.",
      "checkpoint": {
        "question": "Per this reading, which two distinct ATT&CK for ICS techniques does the Industroyer/CRASHOVERRIDE incident illustrate, and what does each one specifically describe?",
        "options": [
          "T0855 (Unauthorized Command Message) for sending a breaker-open command the relays were never meant to accept, and T0831 (Manipulation of Control) for the resulting change in the breaker's physical state",
          "T0836 (Modify Parameter) for sending the breaker-open command, and T0886 (Remote Services) for the resulting change in the breaker's physical state",
          "T0812 (Default Credentials) for sending the breaker-open command, and T0883 (Internet Accessible Device) for the resulting change in the breaker's physical state",
          "Only one technique, T0855, since this reading states Industroyer's breaker manipulation was never assigned any other ATT&CK for ICS technique"
        ],
        "answer": 0,
        "explanation": "This reading names both techniques precisely: T0855 (Unauthorized Command Message, Impair Process Control) for the command itself, and T0831 (Manipulation of Control, Impact) for the resulting breaker-state change -- two separate techniques describing two separate facts about the same incident. Option b swaps in T0836 (Stuxnet's technique, per this room's previous reading) and T0886 (TRITON's technique), neither of which this reading assigns to Industroyer. Option c invents T0812 and T0883 for this incident -- those two are the Oldsmar-pattern techniques this same reading covers in its second half, not Industroyer's. Option d is false; this reading explicitly names two techniques, not one."
      },
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "ot-q2",
      "question": "An investigator reconstructing the 2016 Ukraine substation incident finds: (1) a device dual-homed on both the IT and ICS networks was used to bridge into the ICS environment, and (2) once inside, the malware sent commands directly to protective relays, toggling breakers open, in a form those relays were never meant to accept from that source. Which two ATT&CK for ICS techniques describe steps (1) and (2), in order, and which tactic does step (2) belong to?",
      "options": [
        "T0886 (Remote Services) for step (1), then T0855 (Unauthorized Command Message) for step (2) -- step (2) belongs to the Impair Process Control tactic (TA0106)",
        "T0855 (Unauthorized Command Message) for step (1), then T0886 (Remote Services) for step (2) -- step (2) belongs to the Discovery tactic",
        "T0836 (Modify Parameter) for step (1), then T0812 (Default Credentials) for step (2) -- step (2) belongs to the Initial Access tactic",
        "T0846 (Remote System Discovery) for both steps, since this room documents only one technique for the entire 2016 Ukraine incident"
      ],
      "answer": 0,
      "explanation": "Bridging into the ICS environment via a dual-homed device is T0886 (Remote Services), and the unauthorized breaker-open commands that followed are T0855 (Unauthorized Command Message), which sits under the Impair Process Control tactic (TA0106) -- exactly the order and mapping this room's reading on Industroyer walks. Option b reverses the order and wrongly assigns Discovery to T0886, which this room places under Initial Access and Lateral Movement, never Discovery. Option c substitutes T0836 (Stuxnet's technique) and T0812 (a credential-based Initial Access technique this incident does not involve) for the two real steps described. Option d is false -- this room documents Industroyer with two distinct techniques (T0855 and T0831, per the previous reading), not a single Discovery technique.",
      "xp": 25
    },
    {
      "type": "reading" as const,
      "id": "ot-r5",
      "heading": "Reading the Signs: How an OT Intrusion Actually Looks on the Wire",
      "content": "Everything this room has covered so far converges on one practical question: what does a real intrusion look like crossing an analyst's screen, and how do you tell it apart from Meridian's own routine, entirely legitimate traffic running on the identical protocol and port?\n\n### Sign 1: A Source That Has No Business on the OT Segment\n\nThe first tell in nearly every real IT-to-OT case, including Industroyer's dual-homed pivot, is a source that does not belong. `ENG-WS-02` lives inside Meridian's narrow, well-known `172.20.5.0/24` engineering range and has an established history of talking to `plc-dose-03` and `plc-dose-04`. A corporate-VLAN address, a contractor's laptop, or any host with zero prior Modbus history suddenly appearing on that segment -- regardless of what it does next -- is the single strongest early indicator this room can offer.\n\n### Sign 2: An Address Sweep Across the Controller Range (T0846)\n\nBefore acting, an attacker typically needs to learn what is actually on the segment: which addresses answer, which unit IDs respond. `T0846`, Remote System Discovery (Discovery, TA0102), covers exactly this reconnaissance, with named sub-techniques `T0846.001` (Port Scan) and `T0846.003` (Multicast Discovery). On the wire this looks like a burst of short, low-byte-count connections from one source hitting a range of controller addresses within seconds -- a pattern no legitimate engineering task produces, because `ENG-WS-02` already knows exactly which controller it needs.\n\n### Sign 3: A Command the Destination Was Never Meant to Accept From That Source (T0855)\n\nThe decisive moment is a **write**, not a read. In Modbus terms: function code `6` or `16` arriving from a source with no engineering history, rather than function code `3` or `4` (a read) from `ENG-WS-02`. `T0855`, Unauthorized Command Message, is MITRE's name for this exact pattern.\n\n### Sign 4: A Parameter or Setpoint Actually Changes (T0836 / T0831)\n\nOnce a write succeeds, the question shifts from 'was an unauthorized command sent' to 'what did it actually change.' A register controlling dosing-pump speed moving to a new value is `T0836` (Modify Parameter) or `T0831` (Manipulation of Control) in progress -- and unlike almost every IT indicator this platform otherwise teaches, this is the one category of finding where the consequence is physical, not informational.\n\n### Sign 5: Firmware or Logic Changes\n\nA PLC's control program itself being uploaded or modified -- rather than a single register value -- is a materially more serious finding, because it can persist across power cycles and silently redefine what 'normal' behavior even means going forward.\n\n### The Discriminator That Matters Most\n\nAcross every sign above, one comparison resolves nearly every case: the same protocol, port, and destination controller can carry opposite verdicts depending on who sent it and what function code they used. `ENG-WS-02` reading holding registers all day is invisible noise. The identical protocol, port, and controller receiving a write from an unfamiliar source is the incident.",
      "checkpoint": {
        "question": "Per this reading, which Modbus function codes indicate a WRITE (the decisive sign of T0855, Unauthorized Command Message, when they arrive from an unfamiliar source), as opposed to a routine READ?",
        "options": [
          "Function codes 6 (Write Single Register) and 16 (Write Multiple Registers) indicate a write; function codes 3 and 4 indicate a read",
          "Function codes 3 and 4 indicate a write; function codes 6 and 16 indicate a read",
          "Any function code above 20 indicates a write, and any function code below 20 indicates a read, regardless of its specific number",
          "Modbus function codes do not distinguish reads from writes at all -- only the destination port number determines which operation occurred"
        ],
        "answer": 0,
        "explanation": "This reading states plainly: function code 6 (Write Single Register) or 16 (Write Multiple Registers) is a write, while function code 3 or 4 is a read. Option b reverses the mapping entirely. Option c invents a numeric threshold this reading never states. Option d is false and contradicts this room's own protocol reading -- the destination port (502) is identical for both reads and writes, so it carries no information about which operation occurred; the function code is what distinguishes them."
      },
      "xp": 5
    },
    {
      "type": "log_analysis" as const,
      "id": "ot-la1",
      "heading": "Investigate: An Unauthorized Modbus Write to a Dosing-Pump Controller",
      "context": "You are reviewing Meridian Valley Water Authority's passive OT sensor feed. OT-SENSOR-02, a Corelight (Zeek) sensor mirrored off the plant floor's SPAN port, decoded the session below on the morning shift. There is no endpoint agent anywhere on this segment -- everything you know about this event comes from the wire.",
      "event": {
        "id": "ot-la-modbus-write-001",
        "ts": "2026-08-19T09:41:07.000Z",
        "source": "ids",
        "vendor": "Corelight (Zeek)",
        "event_type": "net_connection",
        "hostname": "OT-SENSOR-02",
        "src_ip": "10.50.12.77",
        "dst_ip": "172.20.5.40",
        "dst_port": 502,
        "protocol": "tcp",
        "severity": "critical",
        "mitre_technique": "T0855",
        "mitre_tactic": "Impair Process Control",
        "edr_scope": "non_edr",
        "description": "Zeek decoded a Modbus WRITE_MULTIPLE_REGISTERS (function code 16) session from 10.50.12.77 -- an address on the corporate/contractor VLAN -- to plc-dose-03 (172.20.5.40), the controller that sets chemical-dosing pump speed on Line 3 at Meridian Water Treatment Plant 3. This source has no prior Modbus history with this controller.",
        "raw": {
          "event.dataset": "corelight.modbus",
          "event.module": "corelight",
          "event.category": "network",
          "event.action": "modbus-write",
          "event.outcome": "success",
          "source.ip": "10.50.12.77",
          "source.port": 51290,
          "destination.ip": "172.20.5.40",
          "destination.port": 502,
          "destination.hostname": "plc-dose-03",
          "network.transport": "tcp",
          "network.protocol": "modbus",
          "network.bytes": 302,
          "network.community_id": "1:aB3xY9mQ2kLp7rTv0Ns1cWzHdE=",
          "zeek.conn.uid": "CxT7pQ2mV9nL1yR4kd",
          "zeek.modbus.func": "WRITE_MULTIPLE_REGISTERS",
          "zeek.modbus.unit_id": 1,
          "zeek.modbus.address": 40020,
          "zeek.modbus.quantity": 2,
          "zeek.modbus.values": "1500,1",
          "zeek.modbus.request_response": "REQUEST",
          "zeek.modbus.tid": 8842,
          "session.duration": 0.021,
          "message": "Modbus WRITE_MULTIPLE_REGISTERS from 10.50.12.77 to 172.20.5.40 unit 1, 2 registers @40020."
        }
      },
      "questions": [
        {
          "question": "Which decoded Zeek field in this event is the clearest proof that 10.50.12.77 issued a WRITE rather than routine read polling, and why does that distinction matter for a chemical-dosing controller specifically?",
          "options": [
            "zeek.modbus.func, whose value WRITE_MULTIPLE_REGISTERS means the session set new register values rather than merely retrieving them -- on a dosing-pump controller, a write can change the actual chemical concentration the pump delivers, not just what a screen displays",
            "destination.port, since this event's destination port value of 502 is, by itself and independent of any function code or any other decoded field Zeek records alongside it, always sufficient on its own to prove a write rather than a read occurred",
            "network.bytes, since this room defines any Modbus session carrying more than exactly 300 bytes of payload as Zeek's own built-in, hard-coded threshold for classifying a session as a write rather than a read",
            "session.duration, since writes always take measurably longer to complete than reads, and this particular session's 0.021-second duration is unusually long specifically for a read rather than a write"
          ],
          "answer": 0,
          "explanation": "zeek.modbus.func recording WRITE_MULTIPLE_REGISTERS is the decisive, decoded field -- it directly states this session set register values rather than reading them, and on plc-dose-03 that means the actual dosing-pump speed the physical process runs on, not merely a number an operator sees on a screen. destination.port (502) is identical for every Modbus session on this segment, read or write, so it carries no directional signal at all. network.bytes has no fixed write/read threshold; byte counts vary with how many registers are involved, not with direction. session.duration carries no such rule either -- this room's earlier benign control event (ENG-WS-02's own scheduled write) has a comparably short duration, so duration alone proves nothing about legitimacy or direction.",
          "xp": 20
        },
        {
          "question": "What single fact about the source 10.50.12.77 should make an analyst treat this event as suspicious rather than routine engineering traffic, independent of the function code involved?",
          "options": [
            "It sits outside Meridian's known 172.20.5.0/24 OT engineering range and has no prior Modbus history with plc-dose-03 -- exactly the 'source that has no business on the segment' pattern this room's reading on signs of intrusion names as the strongest early indicator",
            "It uses TCP as its transport protocol for this session, and this room's protocol reading establishes that TCP is used exclusively by attackers conducting reconnaissance or attacks on OT networks, and is never used by any legitimate engineering workstation",
            "Its source port value of 51290 happens to be an even number, and this room establishes as a general rule that every legitimate Modbus session on Meridian's segment must originate from an odd-numbered source port rather than an even-numbered one",
            "It connected to plc-dose-03 during ordinary business hours rather than overnight, and this room establishes as a general rule that any OT traffic occurring during standard business hours should always be treated as inherently suspicious"
          ],
          "answer": 0,
          "explanation": "10.50.12.77 sits outside Meridian's 172.20.5.0/24 engineering range and has no established Modbus history with plc-dose-03 -- exactly the strongest early indicator this room's 'signs of intrusion' reading names, independent of whatever function code the source later uses. TCP is the standard transport for every Modbus/TCP session on this segment, legitimate or not, so its mere presence carries no signal. This room never states any rule about source-port parity (option c is invented). Business-hours timing is not treated as inherently suspicious anywhere in this room -- the analyst_choice task later in this room shows a legitimate write happening at 02:15, outside business hours entirely, which directly contradicts option d's invented rule.",
          "xp": 20
        }
      ]
    },
    {
      "type": "analyst_choice" as const,
      "id": "ot-ac1",
      "heading": "Triage: A Modbus Write During a Documented Maintenance Window",
      "scenario": "A separate alert fires for a Modbus WRITE_MULTIPLE_REGISTERS burst from 172.20.5.9 to plc-dose-04, recorded by the same OT-SENSOR-02 sensor. The underlying detection rule matches ANY Modbus write function code on the segment, with no allowance for the source address or Meridian's own maintenance schedule.",
      "event": {
        "id": "ot-ac-scheduled-firmware-001",
        "ts": "2026-08-19T02:15:00.000Z",
        "source": "ids",
        "vendor": "Corelight (Zeek)",
        "event_type": "net_connection",
        "hostname": "OT-SENSOR-02",
        "src_ip": "172.20.5.9",
        "dst_ip": "172.20.5.41",
        "dst_port": 502,
        "protocol": "tcp",
        "severity": "medium",
        "user_title": "OT Engineering Workstation",
        "description": "Zeek decoded a burst of Modbus WRITE_MULTIPLE_REGISTERS sessions from 172.20.5.9 (ENG-WS-02, the plant's engineering workstation) to plc-dose-04 (172.20.5.41), writing new setpoint values across roughly ninety seconds at 02:15 local time.",
        "it_verify_result": "confirmed",
        "it_verify_message": "Confirmed against Meridian's change log: this matches scheduled maintenance ticket MAINT-2026-0819, a documented quarterly setpoint recalibration for the Line 4 dosing pump, performed from ENG-WS-02 -- the plant's sole authorized engineering station for this line -- during the approved 02:00-03:00 maintenance window while the line was offline.",
        "raw": {
          "event.dataset": "corelight.modbus",
          "event.module": "corelight",
          "event.category": "network",
          "event.action": "modbus-write",
          "event.outcome": "success",
          "source.ip": "172.20.5.9",
          "source.port": 52011,
          "source.hostname": "eng-ws-02",
          "destination.ip": "172.20.5.41",
          "destination.port": 502,
          "destination.hostname": "plc-dose-04",
          "network.transport": "tcp",
          "network.protocol": "modbus",
          "network.bytes": 296,
          "network.community_id": "1:qR2wT8nY4kLp1rXv7Ms3cWzAdF=",
          "zeek.conn.uid": "DmR4tS8pW2qN6yL1kd",
          "zeek.modbus.func": "WRITE_MULTIPLE_REGISTERS",
          "zeek.modbus.unit_id": 1,
          "zeek.modbus.address": 40030,
          "zeek.modbus.quantity": 2,
          "zeek.modbus.values": "1200,0",
          "zeek.modbus.request_response": "REQUEST",
          "zeek.modbus.tid": 4471,
          "session.duration": 0.017,
          "message": "Modbus WRITE_MULTIPLE_REGISTERS from 172.20.5.9 to 172.20.5.41 unit 1, 2 registers @40030."
        }
      },
      "correct_verdict": "false_positive",
      "explanation": "Every discriminator this room's readings name checks out as legitimate: the source, 172.20.5.9 (ENG-WS-02), sits inside Meridian's own 172.20.5.0/24 engineering range and is the plant's sole authorized engineering workstation for Line 4; the it_verify_message confirms a documented, ticketed maintenance window (MAINT-2026-0819) for a quarterly setpoint recalibration, performed while the line was offline; and the timing (02:15, inside the approved 02:00-03:00 window) matches the ticket exactly. This is the legitimate write shape this room's protocol reading warned about: it produces the identical Modbus function code (WRITE_MULTIPLE_REGISTERS) as the ot-la1 attack pattern, and only the surrounding context -- not the function code itself -- tells them apart.",
      "fp_trap": "A student who has just learned that writes are the decisive sign of T0855 is primed to escalate reflexively on seeing ANY write function code -- that is exactly the overcorrection this task exists to catch. This room's own protocol reading was explicit that a write function code alone never resolves the verdict on an authenticationless protocol; the source's identity, its membership in the sanctioned engineering range, and independent confirmation of a documented change ticket are what actually decide the case.",
      "xp": 25
    },
    {
      "type": "reading" as const,
      "id": "ot-r6",
      "heading": "Why You Cannot Put EDR on a PLC: Passive Monitoring With Zeek and Suricata",
      "content": "Everything this platform teaches elsewhere about detection assumes an agent runs on the endpoint -- Sysmon on a Windows host, an EDR sensor reporting process creation. None of that is possible on `plc-dose-03` or `plc-dose-04`, and understanding exactly why reframes how OT detection has to work.\n\n### Why There Is No Endpoint Agent\n\nA PLC like `plc-dose-03` runs a minimal, vendor-proprietary real-time operating system with barely enough spare CPU and memory to run its own control logic, let alone a third-party security agent competing for those same resources. Installing unapproved software on a certified control device can void the manufacturer's support agreement outright and, more seriously, can invalidate the device's safety certification -- granted for one exact, tested software configuration. The practical consequence: almost nothing at Purdue Level 0 or 1 can run an agent at all.\n\n### Passive Network Monitoring: SPAN Ports and TAPs\n\nOT visibility is built almost entirely on **passive** network monitoring -- a sensor that only reads a copy of traffic and never sits inline where it could introduce latency or a single point of failure into a safety-critical control loop. A **SPAN port** (Switched Port Analyzer, also called port mirroring) configured on a switch duplicates traffic to a monitoring port; a **TAP** (network Test Access Point) is dedicated hardware that physically copies every bit crossing a cable without touching the original signal path. Either way, `OT-SENSOR-02` sees everything and changes nothing.\n\n### Zeek: Reconstructing Protocol-Level Meaning\n\n**Zeek** (formerly Bro) is an open-source network security monitor that reconstructs full application-layer meaning from raw traffic. For OT specifically, Zeek ships protocol analyzers that decode Modbus and other industrial protocols directly, turning an opaque byte stream into structured, readable fields -- the exact function code used, the unit ID addressed, the register address and value involved. This is precisely what let you answer this room's log_analysis questions without ever touching `plc-dose-03` itself.\n\n### Suricata: Signature-Based Alerting on the Wire\n\n**Suricata** is an open-source intrusion detection engine that evaluates traffic against a signature ruleset, with ICS-aware rules purpose-built to fire on OT-specific patterns: a Modbus client enumerating multiple unit IDs from outside the known engineering block, or a write function code reaching a controller from anywhere other than `ENG-WS-02`. These signatures give a SOC an immediate alert the moment one of this room's warning signs appears on the wire, without requiring manual inspection of every Zeek log line.",
      "checkpoint": {
        "question": "Per this reading, why can almost nothing at Purdue Level 0 or Level 1 run a security agent, and what mechanism gives OT-SENSOR-02 visibility instead?",
        "options": [
          "PLCs run minimal, vendor-proprietary real-time operating systems with little spare capacity, and installing unapproved software can void support agreements and invalidate safety certifications -- so visibility instead comes from passive monitoring via a SPAN port or TAP that copies traffic without touching it",
          "PLCs can actually run any standard commercial security agent without any restriction whatsoever, but this reading states Meridian has simply chosen, purely for budget reasons this reading names directly, not to install one on any of its controllers",
          "PLCs are physically incapable of connecting to any network at all under any circumstances, so this reading concludes that no monitoring of any kind, whether passive or active, is technically possible anywhere on this entire OT segment",
          "Suricata itself is installed directly on plc-dose-03, running as a lightweight software agent this reading describes as specifically designed to operate within a real-time operating system's limited resources"
        ],
        "answer": 0,
        "explanation": "This reading states the reason precisely: minimal proprietary real-time OS with little spare capacity, plus the real risk of voiding support agreements and invalidating safety certifications, and states the alternative directly: passive monitoring via a SPAN port or TAP. Option b is false -- this reading never attributes the absence of an agent to a budget decision; it is a structural, safety-certification-driven constraint. Option c is false and contradicted throughout this room -- plc-dose-03 and plc-dose-04 both communicate over Modbus/TCP constantly, which requires a network connection. Option d directly contradicts this reading, which states Suricata and Zeek run on the passive sensor (OT-SENSOR-02), never on the PLC itself."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "ot-r7",
      "heading": "Segmentation, Allowlisting, and Responding Without Breaking the Plant",
      "content": "Passive monitoring detects; it does not prevent, and a confirmed OT finding demands a response that fits an environment where blunt IT-style containment can itself cause harm.\n\n### Command Allowlisting and the Industrial DMZ\n\nCommand allowlisting restricts which source addresses may issue write function codes to a given controller at all -- at Meridian, only `ENG-WS-02` should ever be permitted to write to `plc-dose-03` or `plc-dose-04`, so that even an attacker who reaches the segment cannot get a write forwarded. Network segmentation enforces the Purdue Model's Level 3.5 Industrial DMZ boundary in practice: a firewall requiring all north-south IT-to-OT traffic to pass through a controlled, logged chokepoint rather than connecting directly -- precisely the boundary Industroyer's dual-homed device, and this room's own log_analysis event, both crossed uncontrolled.\n\n### Responding Without Making It Worse\n\nOT containment is not workstation containment, and three IT-trained instincts are actively dangerous here. First, you cannot push an EDR isolation action to a PLC -- no agent runs there, so there is nothing to isolate remotely; containment happens at the network layer instead, cutting the offending source off at the segment boundary. Second, do not blindly power-cycle a live controller to 'flush' a bad write -- rebooting a controller driving a physical process can itself disrupt that process and destroys volatile evidence a reboot cannot recover. Third, do not blanket-block the entire protocol port across the site -- blocking all of TCP `502`, for instance, also blocks `ENG-WS-02`'s own legitimate read-only polling that keeps operators informed of the process, and must be coordinated with plant operations rather than done unilaterally by a SOC alone.\n\nThe response that actually fits the evidence: cut the unauthorized source off at the IT/OT boundary (the segmentation this section just covered), and bring in the plant's own process engineers to compare the affected registers against their intended values and revert safely -- because a confirmed write can have already changed something the physical process depends on.\n\n### Where to Go for Authoritative Guidance\n\nNIST Special Publication 800-82 Revision 3, Guide to Operational Technology (OT) Security, is the standard reference for this entire architecture -- defense-in-depth, Purdue-level-aware network design, and OT-specific access control. CISA's ICS advisories program publishes an ongoing stream of vulnerability disclosures specific to named ICS/SCADA products -- the closest OT equivalent to the CVE feeds a SOC analyst already tracks for IT systems.",
      "checkpoint": {
        "question": "Per this reading, why is blanket-blocking all TCP port 502 traffic across the entire Meridian site a dangerous response to a confirmed unauthorized Modbus write, rather than a clean fix?",
        "options": [
          "Because it also blocks ENG-WS-02's own legitimate read-only polling that keeps operators informed of the process, and must be coordinated with plant operations rather than done unilaterally by a SOC alone",
          "Because TCP port 502 is legally protected by federal regulation and blocking it exposes the utility to fines regardless of the security justification",
          "Because Modbus/TCP automatically reroutes to a random port if port 502 is blocked, making the block completely ineffective within seconds",
          "Because blocking port 502 has no actual effect on Modbus traffic at all, since Modbus does not use TCP as its transport protocol"
        ],
        "answer": 0,
        "explanation": "This reading states the real cost directly: blanket-blocking 502 blocks ENG-WS-02's own legitimate polling that keeps operators informed, and any such block must be coordinated with plant operations rather than done unilaterally. No such federal-fine rule is stated anywhere in this reading (option b is invented). Modbus/TCP has no automatic port-hopping or rerouting behavior (option c is invented and technically false). Option d directly contradicts this room's protocol reading, which states Modbus/TCP explicitly uses TCP as its transport and port 502 specifically."
      },
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "ot-q3",
      "question": "You have confirmed an unauthorized Modbus write to plc-dose-03 from a corporate-VLAN address, and Meridian has no EDR agent on any controller. What response fits both the evidence and this room's guidance?",
      "options": [
        "Cut the offending source off at the IT/OT boundary, and have Meridian's process engineers compare the written registers against their intended values and revert safely -- no agent exists on the PLC to isolate it directly",
        "Push an EDR network-isolation action directly to plc-dose-03, exactly the containment you would apply to a compromised employee laptop",
        "Immediately power-cycle plc-dose-03 to flush the written registers, and consider the incident closed once the controller resumes normal operation",
        "Block all TCP port 502 traffic across the entire plant network at once, since that halts the write immediately with no need to coordinate with plant operations"
      ],
      "answer": 0,
      "explanation": "This room's response reading states exactly this: cut the unauthorized source off at the IT/OT boundary, and bring in process engineers to verify and revert the affected registers, because no agent exists on a PLC to isolate it directly. Option b is impossible -- a PLC runs no EDR sensor, so there is no isolation action to push. Option c is dangerous and destroys evidence -- blindly power-cycling a live controller can itself disrupt the physical process and loses volatile state a reboot cannot recover, and it does nothing to identify or stop the source. Option d breaks the plant -- blocking all of port 502 also blocks ENG-WS-02's own legitimate read-only polling, and this room's reading is explicit that any such block must be coordinated with plant operations, not done unilaterally.",
      "xp": 25
    },
    {
      "type": "question" as const,
      "id": "ot-q4",
      "question": "Reconstruct this room's full chain in order: an unauthorized source reaches Meridian's OT segment, sweeps the controller range, then issues a register write to plc-dose-03. Which three ATT&CK for ICS technique IDs describe these three steps, in order, and which single fact -- true throughout the chain -- explains why Modbus/TCP itself never blocked any of them?",
      "options": [
        "T0886 (crossing onto the segment), T0846 (the sweep), T0855 (the write) -- and Modbus/TCP has no authentication at all, so the protocol could not distinguish the unauthorized source from Meridian's own engineering workstation at any step",
        "T0855 (crossing onto the segment), T0886 (the sweep), T0836 (the write) -- and Modbus/TCP encrypts every session, so the write must have used a stolen certificate",
        "T0846 (crossing onto the segment), T0812 (the sweep), T0831 (the write) -- and Modbus/TCP requires a username and password for every function code",
        "T0883 (crossing onto the segment), T0836 (the sweep), T0814 (the write) -- and Modbus/TCP silently blocks any write from outside the 172.20.5.0/24 range by design"
      ],
      "answer": 0,
      "explanation": "This is the exact order this room's readings walked: T0886 (Remote Services) for reaching the OT segment, T0846 (Remote System Discovery) for the address sweep, and T0855 (Unauthorized Command Message) for the write -- and this room's protocol reading is explicit that Modbus/TCP has no authentication at all, so it cannot tell an unauthorized source apart from ENG-WS-02 at any step. Option b, c, and d all scramble the technique order and, worse, invent security properties this room's protocol reading explicitly denies Modbus/TCP has: universal encryption requiring a stolen certificate, a username/password requirement, or an automatic IP-range block -- none of these exist in the real protocol, which is the entire reason this room's signs-of-intrusion reading has to rely on source identity and function code instead.",
      "xp": 25
    },
    {
      "type": "flag" as const,
      "id": "ot-f1",
      "prompt": "This room's log_analysis task investigates a Modbus WRITE_MULTIPLE_REGISTERS session sent to plc-dose-03 from a source with no engineering history. What MITRE ATT&CK for ICS technique ID names sending a command message that instructs a control-system device to act outside its intended function, or without the operational authorization to do so -- exactly what that session represents?",
      "answer": "T0855",
      "hint": "Covered in this room's reading 'Reading the Signs: How an OT Intrusion Actually Looks on the Wire,' under 'Sign 3.'",
      "xp": 15
    }
  ]
};

export const roomsBatch47 = [otIcsSecurityRoom];
