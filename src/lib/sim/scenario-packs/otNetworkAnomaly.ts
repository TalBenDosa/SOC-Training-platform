/**
 * Scenario pack: "OT/ICS Intrusion — A Corporate Host Writes to a PLC (Network-Only Visibility)"
 *
 * ADVANCED tier. An entirely new estate: the plant floor. Here there are no
 * endpoint agents — you cannot install EDR on a programmable logic controller —
 * so ALL visibility comes from passive network sensors watching the wire. Two
 * feed the case: a Corelight (Zeek) sensor that reconstructs connections and
 * decodes the Modbus/TCP industrial protocol, and a Suricata IDS running
 * ICS-aware signatures. That is how OT is actually monitored in the field.
 *
 * The incident is an IT→OT crossing. A host from the corporate VLAN (10.20.8.44)
 * that has no business on the plant network starts speaking Modbus/TCP (port 502)
 * to programmable controllers it has never contacted. It first sweeps a range of
 * controller addresses — a device/point discovery — and then issues Modbus WRITE
 * function codes (6, Write Single Register; 16, Write Multiple Registers) to one
 * of them, PLC-LINE1-01. A write to a controller is the impact: it changes a
 * value the physical process runs on.
 *
 * The teaching spine is that "industrial-protocol traffic to a PLC" is not by
 * itself the incident — the plant's own engineering station does exactly that,
 * all day. A benign control is included on purpose: the authorized operator
 * station ENG-HMI-01 (172.16.30.5) polling the same controllers with Modbus READ
 * function codes. Same protocol, same port, same PLCs — opposite verdict. The
 * discriminators are the source identity (an OT-resident engineering host vs a
 * corporate host that crossed the segment boundary) and the function code
 * (read-only polling vs a register write).
 *
 * SOURCES (registry vendor keys only): corelight-zeek (the conn-log connection
 * records and the Modbus protocol decode — read vs write function codes), and
 * suricata (the ICS IDS signatures on the enumeration and the write).
 *
 * MITRE ATT&CK for ICS: T0886 (Remote Services — the corporate host reaching the
 * OT segment), T0846 (Remote System Discovery — the address sweep), T0855
 * (Unauthorized Command Message — the write function code), T0836 (Modify
 * Parameter — the register value change).
 *
 * NOTE: register in scenarios.ts with difficulty "advanced" (the ScenarioBundle
 * itself carries no difficulty field). This file is authored standalone.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";

export function buildOtNetworkAnomalyScenario(scenarioId = "ot-network-anomaly-2026"): ScenarioBundle {
  const B = new Date("2026-08-28T22:10:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One case — the whole IT→OT crossing is a single incident.
  const INCIDENT = "inc:ot-network-anomaly:1";

  // The passive sensors that are the only telemetry on this segment.
  const sensor = { hostname: "OT-SENSOR-01" };

  // The corporate-VLAN host that crossed into OT and has no business there.
  const attackerIp = "10.20.8.44";

  // The OT/production VLAN 172.16.30.0/24 and its controllers.
  const plc1 = { ip: "172.16.30.11", host: "plc-line1-01" }; // the write target
  const plc2 = { ip: "172.16.30.12", host: "plc-line1-02" }; // swept during discovery
  const plc3 = { ip: "172.16.30.13" };                        // swept during discovery

  // The benign control: the authorized, OT-resident engineering / operator station.
  const engHmi = { ip: "172.16.30.5", host: "eng-hmi-01" };

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — the authorized engineering station polling the PLCs.
    //    Zeek decodes Modbus READ_HOLDING_REGISTERS from ENG-HMI-01 to the same
    //    controllers the attack later writes to. Same protocol, same port, same
    //    PLCs — the difference is the source identity and the READ function code.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ot_00_benign_hmi_poll",
      ts: "2026-08-28T14:03:07Z",
      source: "ids",
      vendor: "Corelight (Zeek)",
      event_type: "net_connection",
      hostname: sensor.hostname,
      src_ip: engHmi.ip,
      dst_ip: plc1.ip,
      dst_port: 502,
      protocol: "tcp",
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        `The control case. ${engHmi.host} (${engHmi.ip}) is the plant's authorized operator/engineering station, and this is its routine job: it polls ${plc1.host} and the other line controllers with Modbus READ_HOLDING_REGISTERS every few seconds to display live values. It is an OT-resident host inside 172.16.30.0/24, it only READS, and it does this around the clock. Same protocol (Modbus/TCP 502) and same PLCs as the incident — but the source is the sanctioned station and the function code is a read, not a write. Contrast with ${attackerIp}, a corporate-VLAN host that crossed into OT and issued WRITE function codes.`,
      description:
        `Zeek decoded a Modbus/TCP session from the engineering station ${engHmi.host} (${engHmi.ip}) to ${plc1.host} (${plc1.ip}) on port 502: function READ_HOLDING_REGISTERS, unit 1, 10 registers from 40001 — one of its continuous read-polling cycles.`,
      raw: {
        "event.dataset": "corelight.modbus",
        "event.module": "corelight",
        "event.category": "network",
        "event.action": "modbus-read",
        "event.outcome": "success",
        "source.ip": engHmi.ip,
        "source.port": 51544,
        "source.hostname": engHmi.host,
        "destination.ip": plc1.ip,
        "destination.port": 502,
        "destination.hostname": plc1.host,
        "network.transport": "tcp",
        "network.protocol": "modbus",
        "network.bytes": 236,
        "network.community_id": "1:0m6P2k9Yq3xQvJm5b1Tq0oHqcTA=",
        "zeek.conn.uid": "Ct9aQ21H8fJ2mQ0d3a",
        "zeek.conn.service": "modbus",
        "zeek.conn.conn_state": "SF",
        "zeek.modbus.func": "READ_HOLDING_REGISTERS",
        "zeek.modbus.unit_id": 1,
        "zeek.modbus.address": 40001,
        "zeek.modbus.quantity": 10,
        "zeek.modbus.request_response": "REQUEST",
        "zeek.modbus.tid": 4471,
        "session.duration": 0.006,
        "message": `Modbus READ_HOLDING_REGISTERS from ${engHmi.ip} to ${plc1.ip} unit 1, 10 registers @40001.`,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE CROSSING — a corporate-VLAN host reaches the OT segment. Zeek's
    //    conn.log shows 10.20.8.44 opening a Modbus/TCP (502) connection to a
    //    controller it has never contacted. A 10.x host talking to a 172.16.x
    //    PLC is the IT→OT boundary being crossed (T0886 Remote Services).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ot_01_it_ot_crossing",
      ts: T(0),
      source: "ids",
      vendor: "Corelight (Zeek)",
      event_type: "net_connection",
      hostname: sensor.hostname,
      src_ip: attackerIp,
      dst_ip: plc1.ip,
      dst_port: 502,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T0886",
      mitre_tactic: "Lateral Movement",
      incident_id: INCIDENT,
      description:
        `Zeek's connection log shows ${attackerIp} — an address on the corporate VLAN — opening a Modbus/TCP session on port 502 to ${plc1.host} (${plc1.ip}) on the production VLAN at 22:10. This source has no prior Modbus history to any controller.`,
      raw: {
        "event.dataset": "corelight.conn",
        "event.module": "corelight",
        "event.category": "network",
        "event.action": "network-flow",
        "event.outcome": "success",
        "source.ip": attackerIp,
        "source.port": 49771,
        "destination.ip": plc1.ip,
        "destination.port": 502,
        "destination.hostname": plc1.host,
        "network.transport": "tcp",
        "network.protocol": "modbus",
        "network.bytes": 312,
        "network.packets": 6,
        "network.community_id": "1:cP4Ym2Xd7bQ9r0Tk1sV3nJpLwE=",
        "zeek.conn.uid": "CqL3mP4bV1nX2yR8kd",
        "zeek.conn.id.orig_h": attackerIp,
        "zeek.conn.id.resp_h": plc1.ip,
        "zeek.conn.id.resp_p": 502,
        "zeek.conn.proto": "tcp",
        "zeek.conn.service": "modbus",
        "zeek.conn.orig_bytes": 132,
        "zeek.conn.resp_bytes": 180,
        "zeek.conn.conn_state": "SF",
        "zeek.conn.history": "ShADadFf",
        "session.duration": 0.221,
        "message": `Modbus/TCP connection ${attackerIp}:49771 -> ${plc1.ip}:502 (service modbus).`,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE ADDRESS SWEEP — the same host touches a range of controllers on
    //    502 in seconds. Zeek logs short, low-byte connections to PLC-LINE1-02
    //    and .13 right after the first. Enumerating which controllers answer is
    //    Remote System Discovery on the OT segment (T0846).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ot_02_point_discovery",
      ts: T(40 * SEC),
      source: "ids",
      vendor: "Corelight (Zeek)",
      event_type: "net_connection",
      hostname: sensor.hostname,
      src_ip: attackerIp,
      dst_ip: plc2.ip,
      dst_port: 502,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T0846",
      mitre_tactic: "Discovery",
      incident_id: INCIDENT,
      description:
        `Within seconds ${attackerIp} opened further short Modbus/TCP connections across the controller range — ${plc2.ip} (${plc2.host}) and ${plc3.ip} — each a brief session probing which unit IDs and registers respond. This one to ${plc2.ip} is representative of the sweep.`,
      raw: {
        "event.dataset": "corelight.conn",
        "event.module": "corelight",
        "event.category": "network",
        "event.action": "network-flow",
        "event.outcome": "success",
        "source.ip": attackerIp,
        "source.port": 49788,
        "destination.ip": plc2.ip,
        "destination.port": 502,
        "destination.hostname": plc2.host,
        "network.transport": "tcp",
        "network.protocol": "modbus",
        "network.bytes": 158,
        "network.packets": 5,
        "network.community_id": "1:hN8Qm3Yd2bX7r1Tk9sV0nJpLwR=",
        "zeek.conn.uid": "Cr7kV2mB9nX1yQ4pd8",
        "zeek.conn.id.orig_h": attackerIp,
        "zeek.conn.id.resp_h": plc2.ip,
        "zeek.conn.id.resp_p": 502,
        "zeek.conn.proto": "tcp",
        "zeek.conn.service": "modbus",
        "zeek.conn.orig_bytes": 84,
        "zeek.conn.resp_bytes": 74,
        "zeek.conn.conn_state": "SF",
        "zeek.conn.history": "ShADadFf",
        "zeek.modbus.func": "READ_DEVICE_IDENTIFICATION",
        "zeek.modbus.unit_id": 1,
        "zeek.modbus.request_response": "REQUEST",
        "session.duration": 0.048,
        "message": `Short Modbus/TCP probe ${attackerIp} -> ${plc2.ip}:502; range sweep across 172.16.30.11-13.`,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. IDS on the sweep — Suricata's ICS ruleset fires on a Modbus client
    //    enumerating the segment from outside the engineering address range.
    //    Supporting alert, not the primary detection.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ot_03_suricata_scan_alert",
      ts: T(52 * SEC),
      source: "ids",
      vendor: "Suricata",
      event_type: "ids_signature",
      hostname: sensor.hostname,
      src_ip: attackerIp,
      dst_ip: plc2.ip,
      dst_port: 502,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T0846",
      mitre_tactic: "Discovery",
      incident_id: INCIDENT,
      description:
        `Suricata raised an ICS signature: a Modbus client at ${attackerIp} enumerating controllers across the production range from outside the sanctioned engineering address block.`,
      raw: {
        "event.module": "suricata",
        "event.dataset": "suricata.eve",
        "src_ip": attackerIp,
        "src_port": 49788,
        "dest_ip": plc2.ip,
        "dest_port": 502,
        "proto": "TCP",
        "event_type": "alert",
        "flow_id": 1884451220037761,
        "alert": {
          "action": "allowed",
          "gid": 1,
          "signature_id": 2620111,
          "rev": 3,
          "signature": "ET MODBUS Modbus Scanning of Multiple Unit IDs from Non-Engineering Source",
          "category": "Potentially Bad Traffic",
          "severity": 2,
          "metadata": {
            "protocol": "modbus",
            "modbus_function": "43/14 read_device_identification",
            "mitre_tactic_id": "TA0102",
            "mitre_technique_id": "T0846",
          },
        },
        "host.name": sensor.hostname,
        "rule.description": "Suricata ICS: Modbus enumeration across controller range from an address outside the engineering block",
        "rule.level": 8,
        "rule.groups": ["ids", "suricata", "modbus", "ot"],
        "message": `Modbus enumeration ${attackerIp} across 172.16.30.11-13 unit IDs.`,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. THE WRITE — a register write to the controller. Zeek's Modbus decode
    //    shows 10.20.8.44 issuing WRITE_SINGLE_REGISTER (function 6) to
    //    PLC-LINE1-01, setting register 40008 to a value. Writing to a
    //    controller changes what the physical process runs on (T0836 / T0855).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ot_04_modbus_write_single",
      ts: T(3 * MIN),
      source: "ids",
      vendor: "Corelight (Zeek)",
      event_type: "net_connection",
      hostname: sensor.hostname,
      src_ip: attackerIp,
      dst_ip: plc1.ip,
      dst_port: 502,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T0836",
      mitre_tactic: "Impair Process Control",
      incident_id: INCIDENT,
      description:
        `Zeek decoded a Modbus WRITE_SINGLE_REGISTER (function code 6) from ${attackerIp} to ${plc1.host} (${plc1.ip}): unit 1, register 40008 set to 0. A write from this source to a line controller changes a value the process depends on.`,
      raw: {
        "event.dataset": "corelight.modbus",
        "event.module": "corelight",
        "event.category": "network",
        "event.action": "modbus-write",
        "event.outcome": "success",
        "source.ip": attackerIp,
        "source.port": 49771,
        "destination.ip": plc1.ip,
        "destination.port": 502,
        "destination.hostname": plc1.host,
        "network.transport": "tcp",
        "network.protocol": "modbus",
        "network.bytes": 288,
        "network.community_id": "1:cP4Ym2Xd7bQ9r0Tk1sV3nJpLwE=",
        "zeek.conn.uid": "CqL3mP4bV1nX2yR8kd",
        "zeek.modbus.func": "WRITE_SINGLE_REGISTER",
        "zeek.modbus.unit_id": 1,
        "zeek.modbus.address": 40008,
        "zeek.modbus.quantity": 1,
        "zeek.modbus.values": "0",
        "zeek.modbus.request_response": "REQUEST",
        "zeek.modbus.tid": 5210,
        "session.duration": 0.014,
        "message": `Modbus WRITE_SINGLE_REGISTER from ${attackerIp} to ${plc1.ip} unit 1 register 40008 = 0.`,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. A SECOND WRITE — a block write to the same controller. Zeek shows
    //    WRITE_MULTIPLE_REGISTERS (function code 16) setting a block of holding
    //    registers, a command message the controller was never meant to take
    //    from this host (T0855 Unauthorized Command Message).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ot_05_modbus_write_multiple",
      ts: T(3 * MIN + 20 * SEC),
      source: "ids",
      vendor: "Corelight (Zeek)",
      event_type: "net_connection",
      hostname: sensor.hostname,
      src_ip: attackerIp,
      dst_ip: plc1.ip,
      dst_port: 502,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T0855",
      mitre_tactic: "Impair Process Control",
      incident_id: INCIDENT,
      description:
        `Twenty seconds later Zeek decoded a Modbus WRITE_MULTIPLE_REGISTERS (function code 16) from ${attackerIp} to ${plc1.host} (${plc1.ip}): unit 1, four holding registers from 40010 written in one command message.`,
      raw: {
        "event.dataset": "corelight.modbus",
        "event.module": "corelight",
        "event.category": "network",
        "event.action": "modbus-write",
        "event.outcome": "success",
        "source.ip": attackerIp,
        "source.port": 49771,
        "destination.ip": plc1.ip,
        "destination.port": 502,
        "destination.hostname": plc1.host,
        "network.transport": "tcp",
        "network.protocol": "modbus",
        "network.bytes": 334,
        "network.community_id": "1:cP4Ym2Xd7bQ9r0Tk1sV3nJpLwE=",
        "zeek.conn.uid": "CqL3mP4bV1nX2yR8kd",
        "zeek.modbus.func": "WRITE_MULTIPLE_REGISTERS",
        "zeek.modbus.unit_id": 1,
        "zeek.modbus.address": 40010,
        "zeek.modbus.quantity": 4,
        "zeek.modbus.values": "0,0,1,0",
        "zeek.modbus.request_response": "REQUEST",
        "zeek.modbus.tid": 5211,
        "session.duration": 0.019,
        "message": `Modbus WRITE_MULTIPLE_REGISTERS from ${attackerIp} to ${plc1.ip} unit 1, 4 registers @40010.`,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE DETECTION — Suricata fires on the Modbus write function code from
    //    a host outside the engineering range. This is the alert that opens the
    //    incident. edr_scope "non_edr": OT has no endpoint agent to pivot to —
    //    the whole investigation lives on the network sensors.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ot_06_suricata_write_detection",
      ts: T(3 * MIN + 30 * SEC),
      source: "ids",
      vendor: "Suricata",
      event_type: "ids_signature",
      hostname: sensor.hostname,
      src_ip: attackerIp,
      dst_ip: plc1.ip,
      dst_port: 502,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T0855",
      mitre_tactic: "Impair Process Control",
      incident_id: INCIDENT,
      is_detection: true,
      edr_scope: "non_edr",
      description:
        `Suricata raised a high-severity ICS detection: a Modbus register-write function code (6/16) sent to ${plc1.host} (${plc1.ip}) from ${attackerIp}, a source outside the plant's engineering address block. This is the alert that opened the case.`,
      raw: {
        "event.module": "suricata",
        "event.dataset": "suricata.eve",
        "src_ip": attackerIp,
        "src_port": 49771,
        "dest_ip": plc1.ip,
        "dest_port": 502,
        "proto": "TCP",
        "event_type": "alert",
        "flow_id": 1884451220041902,
        "alert": {
          "action": "allowed",
          "gid": 1,
          "signature_id": 2620104,
          "rev": 4,
          "signature": "ET MODBUS Modbus Write Request (Function 6/16) to PLC from Non-Engineering Source",
          "category": "Potential Corporate Privacy Violation",
          "severity": 1,
          "metadata": {
            "protocol": "modbus",
            "modbus_function": "6 write_single_register / 16 write_multiple_registers",
            "affected_product": "Programmable_Logic_Controller",
            "mitre_tactic_id": "TA0106",
            "mitre_technique_id": "T0855",
          },
        },
        "host.name": sensor.hostname,
        "rule.description": "Suricata ICS: Modbus write function code to a controller from an address outside the engineering block",
        "rule.level": 12,
        "rule.groups": ["ids", "suricata", "modbus", "ot", "ics"],
        "message": `Modbus WRITE (function 6/16) ${attackerIp} -> ${plc1.ip}:502 unit 1.`,
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 10.20.8.44 — the corporate host that crossed into OT
      first_seen: T(0),
      last_seen: T(3 * MIN + 30 * SEC),
      reputation: "suspicious",
      tags: ["it-vlan-host", "unexpected-on-ot", "affected"],
    },
    {
      type: "ip",
      value: plc1.ip, // 172.16.30.11 — the controller that was written to
      first_seen: "2026-08-28T14:03:07Z",
      last_seen: T(3 * MIN + 30 * SEC),
      reputation: "unknown",
      tags: ["ot-vlan", "plc", "controller", "affected"],
    },
    {
      type: "ip",
      value: plc2.ip, // 172.16.30.12 — a controller touched during the sweep
      first_seen: T(40 * SEC),
      last_seen: T(52 * SEC),
      reputation: "unknown",
      tags: ["ot-vlan", "plc", "swept"],
    },
    {
      type: "host",
      value: plc1.host, // plc-line1-01 — the written-to controller by name
      first_seen: "2026-08-28T14:03:07Z",
      last_seen: T(3 * MIN + 30 * SEC),
      reputation: "unknown",
      tags: ["ot-vlan", "controller", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "The sensors have no agent on any controller — every record here is reconstructed from the wire by Zeek and Suricata. Reading those records, what is the origin event that makes this an incident rather than normal plant traffic?",
      hint: "Look at where the Modbus source sits (its IP range) versus where the controllers sit, and whether that source has any history of talking to them.",
      kind: "single",
      options: [
        { value: "it_ot_cross", label: "A host from the business network reached the plant's controllers over Modbus/TCP 502 — a device it is not the sanctioned station for, talking a protocol it had never used to them before" },
        { value: "plc_fault", label: "A controller on 172.16.30.0/24 rebooted and re-registered itself, and the re-registration traffic is what the sensors recorded as anomalous" },
        { value: "sensor_gap", label: "The passive sensor briefly lost its span port, so the gap in Modbus records is itself the incident being reported" },
        { value: "new_plc", label: "A new controller was commissioned on the line, and its first Modbus handshake with the engineering station is what raised the case" },
      ],
      answer: "it_ot_cross",
      xp: 60,
      explanation:
        "The origin is the crossing. Zeek's conn.log shows 10.20.8.44 — a corporate-VLAN address — opening Modbus/TCP 502 to 172.16.30.11, a controller on the production VLAN it has no prior history with. A 10.x host speaking an industrial protocol to a 172.16.x PLC is the IT→OT boundary being crossed by something that does not belong on that segment (T0886). Everything downstream (the address sweep, the writes) follows from it. (b), (c) and (d) invent benign explanations the records do not support — there is no reboot, no span-port gap, and no commissioning handshake; there is a foreign host issuing Modbus to controllers it never contacted.",
    },
    {
      id: "q2",
      prompt:
        "The authorized station and the corporate host both send Modbus/TCP to PLC-LINE1-01. Which field, above all others, proves the corporate host issued a WRITE to the controller rather than the read-only polling the engineering station does?",
      hint: "Zeek decodes the Modbus payload. Compare that one decoded field between the two sources.",
      kind: "single",
      options: [
        { value: "func_code", label: "The Modbus function code is WRITE_SINGLE_REGISTER (6) and then WRITE_MULTIPLE_REGISTERS (16) from 10.20.8.44 — where the station at 172.16.30.5 shows READ_HOLDING_REGISTERS" },
        { value: "dst_port", label: "The destination port is 502, which by itself distinguishes a write from a read on any Modbus session" },
        { value: "byte_count", label: "The connection carried more bytes than the read sessions, and a higher byte count is what defines a write" },
        { value: "conn_state", label: "The conn_state field reads SF instead of REJ, and an SF state is what marks a Modbus command as a write" },
      ],
      answer: "func_code",
      xp: 70,
      explanation:
        "It is the decoded Modbus function code. Zeek's protocol decode records zeek.modbus.func: for 10.20.8.44 it is WRITE_SINGLE_REGISTER (function 6) and WRITE_MULTIPLE_REGISTERS (function 16); for the engineering station 172.16.30.5 it is READ_HOLDING_REGISTERS. Read the source IP alongside it and the picture is complete — a write, from a host that is not the sanctioned station. (b) is wrong: both reads and writes use port 502, so the port distinguishes nothing. (c) over-reads volume — byte counts vary with register quantity and prove nothing about direction. (d) misreads a field: SF just means the TCP session opened and closed cleanly (it applies equally to the benign reads); it says nothing about read vs write.",
    },
    {
      id: "q3",
      prompt:
        "ENG-HMI-01 (172.16.30.5) sends Modbus to the very same controllers, continuously. Why is that traffic NOT the incident, while 10.20.8.44's is?",
      hint: "Two things separate them: who the source is, and what the source asks the controller to do.",
      kind: "single",
      options: [
        { value: "identity_and_read", label: "That station is the sanctioned operator host living inside the OT range, and it only READS register values to display them — its identity and its read-only access set it apart from a foreign host that WROTE" },
        { value: "hmi_offline", label: "ENG-HMI-01 was offline during the incident window, so its traffic cannot overlap with the malicious session at all" },
        { value: "different_plc", label: "The engineering station only ever talks to a separate controller, so it never touches PLC-LINE1-01 and there is nothing to compare" },
        { value: "encrypted", label: "The engineering station's Modbus is encrypted while the corporate host's is plaintext, and only the plaintext session can be a write" },
      ],
      answer: "identity_and_read",
      xp: 60,
      explanation:
        "Same protocol, same port, same PLCs — the discriminators are source identity and function code. 172.16.30.5 is the plant's authorized operator/engineering station, it lives inside the OT range, and its sessions are READ_HOLDING_REGISTERS: it is reading live values to display them, which is its whole job. 10.20.8.44 is a corporate host that crossed the boundary and issued WRITE function codes. (b) is false — the control event is the station's routine polling of the same controller, shown precisely so you can compare. (c) is false — both sources reach PLC-LINE1-01. (d) is false and technically confused: standard Modbus/TCP is plaintext for both, and encryption has nothing to do with read vs write.",
    },
    {
      id: "q4",
      prompt:
        "Before the writes, 10.20.8.44 opened a run of brief Modbus/TCP connections to 172.16.30.11, .12 and .13 within seconds. What is that activity, in ATT&CK-for-ICS terms?",
      hint: "Short, low-byte sessions to a range of addresses, back to back — what is the source trying to learn?",
      kind: "single",
      options: [
        { value: "discovery", label: "Remote System Discovery — the host is probing a range of controller addresses to map which units answer and what they expose, before acting on one" },
        { value: "beacon", label: "Command-and-control beaconing — the evenly spaced short sessions are check-ins to an external controller node for instructions" },
        { value: "backup", label: "A scheduled configuration backup pulling each controller's program, which normally produces exactly this burst of short connections" },
        { value: "failover", label: "Redundancy failover between controllers, where the range of short sessions is the line switching to standby units" },
      ],
      answer: "discovery",
      xp: 55,
      explanation:
        "That burst is device/point discovery — Remote System Discovery (T0846). Short, low-byte Modbus sessions swept across 172.16.30.11-13 in seconds are the host asking each controller which unit IDs and registers respond, building a map before it writes. (b) is wrong: this is inbound enumeration of the local controller range, not periodic outbound check-ins to an external node. (c) misattributes it — a configuration backup comes from the engineering station over its normal tooling, not from a corporate host mid-intrusion, and would not be paired with register writes seconds later. (d) invents a failover the records do not show; failover is controller-to-controller, not a corporate host sweeping the range.",
    },
    {
      id: "q5",
      prompt:
        "You have confirmed the writes. There is no EDR to isolate the PLC, and the controller drives a physical process. What response fits the evidence and the environment?",
      hint: "Think about where you CAN cut the traffic, and who has to verify the physical side — not what you would do to an ordinary workstation.",
      kind: "single",
      options: [
        { value: "boundary_and_engineers", label: "Cut the offending host off at the IT/OT boundary, then have the process engineers compare the written registers against their intended values and revert safely — no agent can be placed on the PLC to isolate it" },
        { value: "isolate_plc_edr", label: "Push an EDR network-isolation action to PLC-LINE1-01 to quarantine the controller, exactly the containment you would apply to a compromised employee laptop on the corporate network" },
        { value: "reboot_plc", label: "Remotely power-cycle the controller straight away to flush the written registers, and treat the incident as closed as soon as the PLC comes back and the line resumes" },
        { value: "block_502_all", label: "Block every TCP 502 flow across the entire site at once, since that halts the writes immediately and needs no coordination with the operations or engineering teams" },
      ],
      answer: "boundary_and_engineers",
      xp: 65,
      explanation:
        "OT containment is not workstation containment. You cannot put an agent on a PLC, so you cut the crossing where you can — at the IT/OT boundary (firewall/segmentation) for 10.20.8.44 — and you engage the process engineers to compare the affected registers against their intended values and revert safely, because a write can have moved the physical process. (b) is impossible: a PLC runs no EDR sensor, so there is no isolation action to push. (c) is dangerous — blindly rebooting a live controller can itself disrupt the process and destroys volatile evidence, and it does nothing about the source. (d) breaks the plant: killing all 502 also kills the legitimate engineering polling that keeps operators blind to the line, and it must be coordinated with operations, not done unilaterally.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "OT/ICS Intrusion — A Corporate Host Writes to a PLC (Network-Only Visibility)",
    threat_actor: "IT-to-OT pivot operator issuing industrial-protocol commands from a corporate foothold",
    attack_kind: "ot_ics_intrusion",
    briefing:
      "Passive plant-floor sensors flagged something new overnight: a corporate-side host began exchanging industrial-protocol traffic with programmable controllers it has never contacted, and the IDS raised a signature on a control-function message. Work out what the host did to those controllers, separate it from the site's routine engineering polling, and scope a response for a segment that has no endpoint agents.",
    narrative: `This case lives entirely on the network. The plant floor has no endpoint agents — you cannot install EDR on a programmable logic controller — so the only witnesses are two passive sensors: a Corelight (Zeek) sensor that reconstructs connections and decodes the Modbus/TCP protocol, and a Suricata IDS with ICS-aware signatures.

At 22:10 Zeek's connection log recorded 10.20.8.44 — an address on the corporate VLAN — opening a Modbus/TCP session on port 502 to plc-line1-01 (172.16.30.11) on the production VLAN. That is the origin of the whole case: a host from the business network reaching a controller it has no history with, across the IT/OT boundary. Within seconds it opened a run of short, low-byte connections across the controller range — .11, .12 and .13 — each probing which unit IDs and registers answered. That address sweep is device/point discovery, and Suricata's ICS ruleset fired on a Modbus client enumerating the segment from outside the engineering address block.

Three minutes later the intent became unambiguous. Zeek decoded a Modbus WRITE_SINGLE_REGISTER (function code 6) from 10.20.8.44 to plc-line1-01, setting register 40008, and twenty seconds after that a WRITE_MULTIPLE_REGISTERS (function code 16) writing a block of holding registers from 40010. A write to a controller is not a lookup — it changes a value the physical process runs on. Suricata raised its high-severity detection on the write function code from a non-engineering source, and that alert opened the incident.

The one legitimate comparison is eng-hmi-01 (172.16.30.5), the plant's authorized operator station, polling the very same controllers all day with Modbus READ_HOLDING_REGISTERS. Same protocol, same port, same PLCs — opposite verdict. The tells are the source identity (an OT-resident engineering host versus a corporate host that crossed the boundary) and, decisively, the decoded Modbus function code: a read that displays a value versus a write that sets one.

Because there is no agent on the PLC, containment is an OT problem, not a workstation one: cut the offending host at the IT/OT boundary, and bring in the process engineers to check the written registers against their intended values and revert safely — never blindly reboot a live controller or blanket-block 502, which would blind the legitimate engineering polling too.`,
    learning_objectives: [
      "Investigate an OT/ICS incident with network-only telemetry (Corelight/Zeek connection and Modbus decode, Suricata ICS signatures) because there are no endpoint agents on controllers",
      "Recognise an IT→OT crossing as the origin: a corporate-VLAN host speaking an industrial protocol to controllers it has no history with (T0886)",
      "Read a Modbus decode to tell a register WRITE (function 6/16) apart from read-only polling (READ_HOLDING_REGISTERS), and treat a write to a controller as impact (T0836/T0855)",
      "Distinguish the authorized engineering station's legitimate polling from a foreign host's traffic using source identity and function code, not the protocol or port",
      "Scope OT containment appropriately — cut the crossing at the IT/OT boundary and involve process engineers to verify and revert controller values, rather than applying workstation-style isolation to a PLC",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-28T14:03:07Z", phase: "Baseline", action: `${engHmi.host} (${engHmi.ip}) polls ${plc1.host} with Modbus READ_HOLDING_REGISTERS — the authorized station's routine` },
      { ts: T(0), phase: "Lateral Movement", action: `${attackerIp} (corporate VLAN) opens Modbus/TCP 502 to ${plc1.host} (${plc1.ip}) — IT→OT crossing (T0886)` },
      { ts: T(40 * SEC), phase: "Discovery", action: `${attackerIp} sweeps controllers 172.16.30.11-13 with short Modbus probes — point/device discovery (T0846)` },
      { ts: T(52 * SEC), phase: "Discovery", action: "Suricata ICS signature fires on Modbus enumeration from a non-engineering source" },
      { ts: T(3 * MIN), phase: "Impair Process Control", action: `Modbus WRITE_SINGLE_REGISTER (fc 6) ${attackerIp} → ${plc1.ip} register 40008 (T0836)` },
      { ts: T(3 * MIN + 20 * SEC), phase: "Impair Process Control", action: `Modbus WRITE_MULTIPLE_REGISTERS (fc 16) ${attackerIp} → ${plc1.ip} block @40010 (T0855)` },
      { ts: T(3 * MIN + 30 * SEC), phase: "Detection", action: "Suricata raises the high-severity ICS detection on the write function code from outside the engineering block" },
    ],
    questions,
  };
}
