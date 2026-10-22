/**
 * Scenario pack: "OT/ICS Intrusion, A Corporate Host Writes to a PLC (Network-Only Visibility on the Plant)"
 *
 * ADVANCED tier. An entirely new estate: the plant floor. On the plant side there
 * are no endpoint agents, you cannot install EDR on a programmable logic
 * controller, so ALL plant-side visibility comes from passive network sensors
 * watching the wire. Two feed the case: a Corelight (Zeek) sensor that
 * reconstructs connections and decodes the Modbus/TCP industrial protocol, and a
 * Suricata IDS running ICS-aware signatures. That is how OT is actually monitored
 * in the field. The corporate side of the crossing is ordinary IT: the IT/OT
 * boundary firewall logs the session and the originating corporate workstation
 * runs an EDR.
 *
 * The incident is an IT→OT crossing. A host from the corporate VLAN (10.20.8.44,
 * WKS-NEXA-044) that has no business on the plant network starts speaking
 * Modbus/TCP (port 502) to programmable controllers it has never contacted. It
 * first sweeps a range of controller addresses, a device/point discovery, reads
 * a holding register, and then issues Modbus WRITE function codes (6, Write
 * Single Register; 16, Write Multiple Registers) to one of them, PLC-LINE1-01. A
 * write to a controller is the impact: it changes a value the physical process
 * runs on, and the operator station's next poll shows the new value.
 *
 * The teaching spine is that "industrial-protocol traffic to a PLC" is not by
 * itself the incident, the plant's own engineering station does exactly that,
 * all day. A benign control is included on purpose: the authorized operator
 * station ENG-HMI-01 (172.16.30.5) polling the same controllers with Modbus READ
 * function codes, in the same minutes. Same protocol, same port, same PLCs, 
 * opposite verdict. The discriminators are the source identity (an OT-resident
 * engineering host vs a corporate host that crossed the segment boundary) and the
 * function code (read-only polling vs a register write).
 *
 * SOURCES: corelight-zeek (the conn-log connection records and the Modbus
 * protocol decode, read vs write function codes, requests and responses),
 * suricata (the ICS IDS signatures on the enumeration and the write),
 * palo-alto-ngfw (the IT/OT boundary firewall session) and Microsoft Defender
 * for Endpoint (the corporate origin host).
 *
 * MITRE ATT&CK for ICS: T0886 (Remote Services, the corporate host reaching the
 * OT segment), T0846 (Remote System Discovery, the address sweep), T0855
 * (Unauthorized Command Message, the write function code), T0836 (Modify
 * Parameter, the register value change).
 *
 * NOTE: register in scenarios.ts with difficulty "advanced" (the ScenarioBundle
 * itself carries no difficulty field). This file is authored standalone.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { panConnection } from "@/lib/sim/emitters/paloalto";
import { mdeProcess, mdeNetwork } from "@/lib/sim/emitters/mde";

export function buildOtNetworkAnomalyScenario(scenarioId = "ot-network-anomaly-2026"): ScenarioBundle {
  const B = new Date("2026-08-28T22:10:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One case, the whole IT→OT crossing is a single incident.
  const INCIDENT = "inc:ot-network-anomaly:1";
  const cx = "nexacorp" as const;

  // The passive sensors that are the only telemetry on the plant segment.
  const sensor = { hostname: "OT-SENSOR-01" };

  // The corporate-VLAN host that crossed into OT and has no business there.
  const attackerIp = "10.20.8.44";
  const origin = { hostname: "WKS-NEXA-044", user: "t.rosen@nexacorp.com" };

  // The OT/production VLAN 172.16.30.0/24 and its controllers.
  const plc1 = { ip: "172.16.30.11", host: "plc-line1-01" }; // the write target
  const plc2 = { ip: "172.16.30.12", host: "plc-line1-02" }; // swept during discovery
  const plc3 = { ip: "172.16.30.13" };                        // swept during discovery

  // The benign control: the authorized, OT-resident engineering / operator station.
  const engHmi = { ip: "172.16.30.5", host: "eng-hmi-01" };

  // Setpoint register 40008 is wire offset 7. The HMI reads ten registers from offset 0.
  const regsBefore = "212,0,1,1,3380,17,950,1500,64,2";
  const regsAfter = "212,0,1,1,3380,17,950,0,64,2";

  // One Zeek conn.log record (a TCP session reconstructed from the wire).
  const zeekConn = (o: {
    id: string; at: number; srcPort: number; dst: { ip: string; host?: string }; src?: string; uid: string; cid: string; bytes: number; packets: number;
    orig: number; resp: number; duration: number; severity: TelemetryEvent["severity"]; description: string; extra?: Record<string, string | number>;
    mitre?: string; tactic?: string; incident?: boolean; expected?: TelemetryEvent["expected_verdict"]; fp?: string;
  }): TelemetryEvent => {
    const src = o.src ?? attackerIp;
    return {
      id: o.id, ts: typeof o.at === "number" ? T(o.at) : o.at, source: "ids", vendor: "Corelight (Zeek)", event_type: "net_connection", hostname: sensor.hostname,
      src_ip: src, dst_ip: o.dst.ip, dst_port: 502, protocol: "tcp", severity: o.severity,
      mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incident === false ? undefined : INCIDENT,
      ...(o.expected ? { expected_verdict: o.expected, fp_explanation: o.fp } : {}),
      description: o.description,
      raw: {
        "event.dataset": "corelight.conn",
        "event.module": "corelight",
        "event.category": "network",
        "event.action": "network-flow",
        "event.outcome": "success",
        "source.ip": src,
        "source.port": o.srcPort,
        "destination.ip": o.dst.ip,
        "destination.port": 502,
        "network.transport": "tcp",
        "network.protocol": "modbus",
        "network.bytes": o.bytes,
        "network.packets": o.packets,
        "network.community_id": o.cid,
        "zeek.conn.uid": o.uid,
        "zeek.conn.id.orig_h": src,
        "zeek.conn.id.resp_h": o.dst.ip,
        "zeek.conn.id.resp_p": 502,
        "zeek.conn.proto": "tcp",
        "zeek.conn.service": "modbus",
        "zeek.conn.orig_bytes": o.orig,
        "zeek.conn.resp_bytes": o.resp,
        "zeek.conn.conn_state": "SF",
        "zeek.conn.history": "ShADadFf",
        "session.duration": o.duration,
        ...(o.extra ?? {}),
      },
    };
  };
  // One decoded Modbus message (ICSNPP modbus_detailed.log): request or response.
  const zeekModbus = (o: {
    id: string; ts: string; src?: string; srcPort: number; dst: { ip: string }; uid: string; cid: string; tid: number; func: string; rr: "REQUEST" | "RESPONSE";
    address: number; quantity: number; values?: string; severity: TelemetryEvent["severity"]; description: string;
    mitre?: string; tactic?: string; incident?: boolean; expected?: TelemetryEvent["expected_verdict"]; fp?: string;
  }): TelemetryEvent => {
    const src = o.src ?? attackerIp;
    const write = /WRITE/.test(o.func);
    return {
      id: o.id, ts: o.ts, source: "ids", vendor: "Corelight (Zeek)", event_type: "net_connection", hostname: sensor.hostname,
      src_ip: o.rr === "REQUEST" ? src : o.dst.ip, dst_ip: o.rr === "REQUEST" ? o.dst.ip : src, dst_port: o.rr === "REQUEST" ? 502 : o.srcPort, protocol: "tcp", severity: o.severity,
      mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incident === false ? undefined : INCIDENT,
      ...(o.expected ? { expected_verdict: o.expected, fp_explanation: o.fp } : {}),
      description: o.description,
      raw: {
        "event.dataset": "corelight.modbus",
        "event.module": "corelight",
        "event.category": "network",
        "event.action": write ? "modbus-write" : "modbus-read",
        "event.outcome": "success",
        "source.ip": o.rr === "REQUEST" ? src : o.dst.ip,
        "source.port": o.rr === "REQUEST" ? o.srcPort : 502,
        "destination.ip": o.rr === "REQUEST" ? o.dst.ip : src,
        "destination.port": o.rr === "REQUEST" ? 502 : o.srcPort,
        "network.transport": "tcp",
        "network.protocol": "modbus",
        "network.community_id": o.cid,
        "zeek.conn.uid": o.uid,
        "zeek.conn.service": "modbus",
        "zeek.modbus.func": o.func,
        "zeek.modbus.unit": 1,
        "zeek.modbus.address": o.address,
        "zeek.modbus.quantity": o.quantity,
        ...(o.values !== undefined ? { "zeek.modbus.values": o.values } : {}),
        "zeek.modbus.request_response": o.rr,
        "zeek.modbus.tid": o.tid,
      },
    };
  };
  // The grouping cid values below are the real Community IDs of each flow.
  const cid = {
    hmiA: "1:ngvAnBPEcOlMKIwdY14zJZkCa0g=",
    first: "1:xti2SwThk0vncPhlF0oOw1bTp98=",
    p12: "1:E6vIBNh8IIHRIH+TiUkx6z7DnQg=",
    p13: "1:3GdvQw0AXO5eK00KSpql6Q+h+80=",
    write: "1:9DFnh43UrHhO/IenEueYDNVy3l0=",
    hmiB: "1:5e7df17Sl9oGtiHr50C0G0mbvN8=",
    hmiC: "1:sQILM8mPwtHrB6rFAvH99JRMPgM=",
    readSess: "1:Abc1hc8RzrDoao+M1TzyGrOIwfw=",
  };

  const hmiNote = "The control case. eng-hmi-01 (172.16.30.5) is the plant's authorized operator/engineering station, and this is its routine job: it polls plc-line1-01 and the other line controllers with Modbus READ_HOLDING_REGISTERS every few seconds to display live values. It is an OT-resident host inside 172.16.30.0/24, it only READS, and it does this around the clock, including in the minutes of the incident. Same protocol (Modbus/TCP 502) and same PLCs as the incident, but the source is the sanctioned station and the function code is a read, not a write. Contrast with 10.20.8.44, a corporate-VLAN host that crossed into OT and issued WRITE function codes.";

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL, the authorized engineering station polling the PLCs.
    //    Zeek decodes Modbus READ_HOLDING_REGISTERS from ENG-HMI-01 to the same
    //    controllers the attack later writes to, before, during and after the
    //    intrusion. The difference is the source identity and the READ function code.
    // ─────────────────────────────────────────────────────────────────────
    zeekModbus({
      id: "evt_ot_00_benign_hmi_poll", ts: "2026-08-28T14:03:07.000Z", src: engHmi.ip, srcPort: 51544, dst: plc1, uid: "Ct9aQ21H8fJ2mQ0d3a", cid: cid.hmiA, tid: 4471,
      func: "READ_HOLDING_REGISTERS", rr: "REQUEST", address: 0, quantity: 10, severity: "informational", incident: false, expected: "fp", fp: hmiNote,
      description: `Zeek decoded a Modbus/TCP request from the engineering station ${engHmi.host} (${engHmi.ip}) to ${plc1.host} (${plc1.ip}) on port 502: function READ_HOLDING_REGISTERS, unit 1, 10 registers from offset 0 (40001), one of its continuous read-polling cycles.`,
    }),
    zeekModbus({
      id: "evt_ot_00b_hmi_poll", ts: T(-3 * SEC), src: engHmi.ip, srcPort: 51560, dst: plc1, uid: "CkB4rT7vN1aZ9mD2xQ", cid: cid.hmiB, tid: 4502,
      func: "READ_HOLDING_REGISTERS", rr: "RESPONSE", address: 0, quantity: 10, values: regsBefore, severity: "informational", incident: false,
      description: `The response to the engineering station's poll of ${plc1.host} three seconds before the intrusion: ten holding registers, offset 7 (40008) reads 1500.`,
    }),
    zeekModbus({
      id: "evt_ot_00c_hmi_poll", ts: T(57 * SEC), src: engHmi.ip, srcPort: 51571, dst: plc1, uid: "CmV8pQ3wX5nY1dK6hb", cid: cid.hmiC, tid: 4519,
      func: "READ_HOLDING_REGISTERS", rr: "RESPONSE", address: 0, quantity: 10, values: regsBefore, severity: "informational", incident: false,
      description: `The engineering station's next poll of ${plc1.host}, a minute into the intrusion: offset 7 still reads 1500.`,
    }),
    zeekModbus({
      id: "evt_ot_00d_hmi_poll", ts: T(3 * MIN + 7 * SEC), src: engHmi.ip, srcPort: 51571, dst: plc1, uid: "CmV8pQ3wX5nY1dK6hb", cid: cid.hmiC, tid: 4584,
      func: "READ_HOLDING_REGISTERS", rr: "RESPONSE", address: 0, quantity: 10, values: regsAfter, severity: "informational", incident: false,
      description: `The engineering station's poll of ${plc1.host} seven seconds after the first write: offset 7 (40008) now reads 0.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE ORIGIN, the corporate workstation starts a Python script, and the IT/OT
    //    boundary firewall allows its session to the controller.
    // ─────────────────────────────────────────────────────────────────────
    mdeProcess({
      companyId: cx, id: "evt_ot_00e_origin_powershell", ts: T(-90 * SEC), host: origin.hostname, user: origin.user, srcIp: attackerIp, incidentId: INCIDENT,
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmdline: "powershell.exe -NoProfile",
      parentName: "explorer.exe", parentPid: 4492, pid: 6240, integrity: "Medium", signed: true, severity: "low",
      description: `PowerShell started on ${origin.hostname}, the corporate workstation at ${attackerIp}.`,
    }),
    mdeProcess({
      companyId: cx, id: "evt_ot_00f_origin_python", ts: T(-12 * SEC), host: origin.hostname, user: origin.user, srcIp: attackerIp, incidentId: INCIDENT,
      processName: "python.exe", processPath: "C:\\Users\\t.rosen\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
      cmdline: "python.exe C:\\Users\\t.rosen\\Downloads\\mbtool.py --targets 172.16.30.11-13 --port 502",
      parentName: "powershell.exe", parentPid: 6240, pid: 7124, integrity: "Medium", signed: true, severity: "high", mitre: "T0846", tactic: "Discovery",
      description: `A Python script, mbtool.py, was started from PowerShell on ${origin.hostname} with the controller range 172.16.30.11-13 and port 502 as arguments.`,
    }),
    (() => {
      const e = panConnection({
        companyId: cx, id: "evt_ot_01a_boundary_firewall", ts: T(-200), host: origin.hostname, user: origin.user, srcIp: attackerIp, incidentId: INCIDENT,
        dstIp: plc1.ip, remotePort: 502, app: "modbus", action: "allow", severity: "medium",
        description: `The IT/OT boundary firewall allowed ${attackerIp} to ${plc1.ip} on port 502 (app modbus) under an IT-to-OT rule.`,
      });
      return { ...e, raw: Object.assign({}, e.raw, { "pan.rule": "IT-OT-Engineering-Access", "pan.from_zone": "corp-it", "pan.to_zone": "ot-line1" }) };
    })(),
    mdeNetwork({
      companyId: cx, id: "evt_ot_00g_origin_connect", ts: T(-100), host: origin.hostname, user: origin.user, srcIp: attackerIp, incidentId: INCIDENT,
      remoteIp: plc1.ip, remotePort: 502, initiatingProcess: "python.exe", severity: "medium",
      description: `python.exe on ${origin.hostname} connected to ${plc1.ip}:502.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE CROSSING, a corporate-VLAN host reaches the OT segment. Zeek's
    //    conn.log shows 10.20.8.44 opening a Modbus/TCP (502) connection to a
    //    controller it has never contacted, and reading a holding register.
    // ─────────────────────────────────────────────────────────────────────
    zeekConn({
      id: "evt_ot_01_it_ot_crossing", at: 0, srcPort: 49771, dst: plc1, uid: "CqL3mP4bV1nX2yR8kd", cid: cid.first, bytes: 312, packets: 6, orig: 132, resp: 180, duration: 0.221,
      severity: "high", mitre: "T0886", tactic: "Lateral Movement",
      description: `Zeek's connection log shows ${attackerIp}, an address on the corporate VLAN, opening a Modbus/TCP session on port 502 to ${plc1.host} (${plc1.ip}) on the production VLAN at 22:10. This source has no prior Modbus history to any controller.`,
    }),
    zeekModbus({
      id: "evt_ot_01b_first_read", ts: T(100), srcPort: 49771, dst: plc1, uid: "CqL3mP4bV1nX2yR8kd", cid: cid.first, tid: 1,
      func: "READ_HOLDING_REGISTERS", rr: "REQUEST", address: 0, quantity: 10, severity: "high",
      description: `The first Modbus message of the session: a READ_HOLDING_REGISTERS request, unit 1, ten registers from offset 0, from ${attackerIp}.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE ADDRESS SWEEP, the same host touches the other controllers on 502 in
    //    seconds. Zeek logs short, low-byte connections to .12 and .13 with a device-
    //    identification probe. Remote System Discovery on the OT segment (T0846).
    // ─────────────────────────────────────────────────────────────────────
    zeekConn({
      id: "evt_ot_02_point_discovery", at: 40 * SEC, srcPort: 49788, dst: plc2, uid: "Cr7kV2mB9nX1yQ4pd8", cid: cid.p12, bytes: 158, packets: 5, orig: 84, resp: 74, duration: 0.048,
      severity: "high", mitre: "T0846", tactic: "Discovery",
      extra: { "zeek.modbus.func": "ENCAP_INTERFACE_TRANSPORT", "zeek.modbus.unit": 1, "zeek.modbus.request_response": "REQUEST" },
      description: `Within seconds ${attackerIp} opened further short Modbus/TCP connections across the controller range, ${plc2.ip} (${plc2.host}) and ${plc3.ip}, each a brief session probing which units respond. This one to ${plc2.ip} is representative of the sweep.`,
    }),
    zeekConn({
      id: "evt_ot_02b_point_discovery", at: 44 * SEC, srcPort: 49795, dst: plc3, uid: "CsM2xP9dK4bV7nQ1fy", cid: cid.p13, bytes: 158, packets: 5, orig: 84, resp: 74, duration: 0.051,
      severity: "high", mitre: "T0846", tactic: "Discovery",
      extra: { "zeek.modbus.func": "ENCAP_INTERFACE_TRANSPORT", "zeek.modbus.unit": 1, "zeek.modbus.request_response": "REQUEST" },
      description: `A second short Modbus/TCP probe from ${attackerIp}, to ${plc3.ip}, four seconds after the first.`,
    }),
    mdeNetwork({
      companyId: cx, id: "evt_ot_02c_origin_connect", ts: T(40 * SEC), host: origin.hostname, user: origin.user, srcIp: attackerIp, incidentId: INCIDENT,
      remoteIp: plc2.ip, remotePort: 502, initiatingProcess: "python.exe", severity: "medium", mitre: "T0846", tactic: "Discovery",
      description: `python.exe on ${origin.hostname} connected to ${plc2.ip}:502.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 4. IDS on the sweep, Suricata's ICS ruleset fires on a Modbus client
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
        "host": sensor.hostname,
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
          "category": "Attempted Information Leak",
          "severity": 2,
          "metadata": {
            "protocol": "modbus",
            "modbus_function": "43/14 read_device_identification",
            "mitre_tactic_id": "TA0102",
            "mitre_technique_id": "T0846",
          },
        },
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. THE BEFORE-VALUE, the host reads the setpoint it is about to change.
    // ─────────────────────────────────────────────────────────────────────
    zeekConn({
      id: "evt_ot_03b_read_session", at: 2 * MIN + 30 * SEC, srcPort: 49780, dst: plc1, uid: "CtN5wR2cH8aJ3pX6ke", cid: cid.readSess, bytes: 211, packets: 6, orig: 78, resp: 133, duration: 0.032,
      severity: "high", mitre: "T0801", tactic: "Collection",
      description: `${attackerIp} opened a new short session to ${plc1.ip}:502 two and a half minutes into the intrusion.`,
    }),
    {
      ...zeekModbus({
        id: "evt_ot_03c_read_setpoint", ts: T(2 * MIN + 30 * SEC + 50), srcPort: 49780, dst: plc1, uid: "CtN5wR2cH8aJ3pX6ke", cid: cid.readSess, tid: 1,
        func: "READ_HOLDING_REGISTERS", rr: "REQUEST", address: 7, quantity: 1, severity: "high",
        description: `${attackerIp} read one holding register from ${plc1.host}: offset 7 (40008).`,
      }),
    },
    zeekModbus({
      id: "evt_ot_03d_read_setpoint_response", ts: T(2 * MIN + 30 * SEC + 64), srcPort: 49780, dst: plc1, uid: "CtN5wR2cH8aJ3pX6ke", cid: cid.readSess, tid: 1,
      func: "READ_HOLDING_REGISTERS", rr: "RESPONSE", address: 7, quantity: 1, values: "1500", severity: "high",
      description: `The controller's response: offset 7 holds 1500, the value before any write.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE WRITE SESSION, a fresh TCP session carries the two writes.
    // ─────────────────────────────────────────────────────────────────────
    zeekConn({
      id: "evt_ot_03e_write_session", at: 3 * MIN, srcPort: 49802, dst: plc1, uid: "CZk9mD2xQ4rT7vN1ay", cid: cid.write, bytes: 1021, packets: 18, orig: 478, resp: 543, duration: 21.4,
      severity: "critical", mitre: "T0855", tactic: "Impair Process Control",
      description: `${attackerIp} opened a new Modbus/TCP session to ${plc1.ip}:502 at 22:13 that stayed open for about twenty-one seconds.`,
    }),
    mdeNetwork({
      companyId: cx, id: "evt_ot_03f_origin_connect", ts: T(3 * MIN - 100), host: origin.hostname, user: origin.user, srcIp: attackerIp, incidentId: INCIDENT,
      remoteIp: plc1.ip, remotePort: 502, initiatingProcess: "python.exe", severity: "high", mitre: "T0855", tactic: "Impair Process Control",
      description: `python.exe on ${origin.hostname} connected again to ${plc1.ip}:502.`,
    }),
    zeekModbus({
      id: "evt_ot_04_modbus_write_single", ts: T(3 * MIN + 150), srcPort: 49802, dst: plc1, uid: "CZk9mD2xQ4rT7vN1ay", cid: cid.write, tid: 1,
      func: "WRITE_SINGLE_REGISTER", rr: "REQUEST", address: 7, quantity: 1, values: "0", severity: "critical", mitre: "T0836", tactic: "Impair Process Control",
      description: `Zeek decoded a Modbus WRITE_SINGLE_REGISTER (function code 6) from ${attackerIp} to ${plc1.host} (${plc1.ip}): unit 1, offset 7 (40008) set to 0. A write from this source to a line controller changes a value the process depends on.`,
    }),
    zeekModbus({
      id: "evt_ot_04b_modbus_write_single_response", ts: T(3 * MIN + 170), srcPort: 49802, dst: plc1, uid: "CZk9mD2xQ4rT7vN1ay", cid: cid.write, tid: 1,
      func: "WRITE_SINGLE_REGISTER", rr: "RESPONSE", address: 7, quantity: 1, values: "0", severity: "critical",
      description: `The controller echoed the write with no exception: the register was changed.`,
    }),
    zeekModbus({
      id: "evt_ot_05_modbus_write_multiple", ts: T(3 * MIN + 20 * SEC), srcPort: 49802, dst: plc1, uid: "CZk9mD2xQ4rT7vN1ay", cid: cid.write, tid: 2,
      func: "WRITE_MULTIPLE_REGISTERS", rr: "REQUEST", address: 9, quantity: 4, values: "0,0,1,0", severity: "critical", mitre: "T0855", tactic: "Impair Process Control",
      description: `Twenty seconds later Zeek decoded a Modbus WRITE_MULTIPLE_REGISTERS (function code 16) from ${attackerIp} to ${plc1.host} (${plc1.ip}): unit 1, four holding registers from offset 9 (40010) written in one command message.`,
    }),
    zeekModbus({
      id: "evt_ot_05b_modbus_write_multiple_response", ts: T(3 * MIN + 20 * SEC + 24), srcPort: 49802, dst: plc1, uid: "CZk9mD2xQ4rT7vN1ay", cid: cid.write, tid: 2,
      func: "WRITE_MULTIPLE_REGISTERS", rr: "RESPONSE", address: 9, quantity: 4, severity: "critical",
      description: `The controller acknowledged the block write with no exception.`,
    }),

    // ─────────────────────────────────────────────────────────────────────
    // 7. THE DETECTION, Suricata fires on the Modbus write function code from
    //    a host outside the engineering range. This is the alert that opens the
    //    incident. The plant side has no endpoint agent; the case opens on the
    //    corporate origin host's EDR as well.
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
      edr_scope: "hybrid",
      description:
        `Suricata raised a high-severity ICS detection: a Modbus register-write function code (6/16) sent to ${plc1.host} (${plc1.ip}) from ${attackerIp}, a source outside the plant's engineering address block. This is the alert that opened the case.`,
      raw: {
        "host": sensor.hostname,
        "src_ip": attackerIp,
        "src_port": 49802,
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
          "category": "Attempted Administrator Privilege Gain",
          "severity": 1,
          "metadata": {
            "protocol": "modbus",
            "modbus_function": "6 write_single_register / 16 write_multiple_registers",
            "affected_product": "Programmable_Logic_Controller",
            "mitre_tactic_id": "TA0106",
            "mitre_technique_id": "T0855",
          },
        },
      },
    },
  ];

  // Declared in the order the records happened, whichever sensor wrote them.
  events.sort((a, b) => a.ts.localeCompare(b.ts));

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 10.20.8.44, the corporate host that crossed into OT
      first_seen: T(-90 * SEC),
      last_seen: T(3 * MIN + 30 * SEC),
      reputation: "suspicious",
      tags: ["it-vlan-host", "unexpected-on-ot", "affected"],
    },
    {
      type: "host",
      value: origin.hostname, // WKS-NEXA-044, the corporate workstation behind 10.20.8.44
      first_seen: T(-90 * SEC),
      last_seen: T(3 * MIN + 30 * SEC),
      reputation: "suspicious",
      tags: ["corporate-workstation", "origin"],
    },
    {
      type: "ip",
      value: plc1.ip, // 172.16.30.11, the controller that was written to
      first_seen: "2026-08-28T14:03:07Z",
      last_seen: T(3 * MIN + 30 * SEC),
      reputation: "unknown",
      tags: ["ot-vlan", "plc", "controller", "affected"],
    },
    {
      type: "ip",
      value: plc2.ip, // 172.16.30.12, a controller touched during the sweep
      first_seen: T(40 * SEC),
      last_seen: T(52 * SEC),
      reputation: "unknown",
      tags: ["ot-vlan", "plc", "swept"],
    },
    {
      type: "ip",
      value: plc3.ip, // 172.16.30.13, the third controller swept
      first_seen: T(44 * SEC),
      last_seen: T(44 * SEC),
      reputation: "unknown",
      tags: ["ot-vlan", "plc", "swept"],
    },
    {
      type: "host",
      value: plc1.host, // plc-line1-01, the written-to controller by name
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
        "On the plant side there is no agent on any controller, every record there is reconstructed from the wire by Zeek and Suricata. Reading those records and the boundary firewall, what is the origin event that makes this an incident rather than normal plant traffic?",
      hint: "Look at where the Modbus source sits (its IP range) versus where the controllers sit, and whether that source has any history of talking to them.",
      kind: "single",
      options: [
        { value: "it_ot_cross", label: "A business-network host reached the plant's controllers over Modbus/TCP 502, not the sanctioned station, and with no history of talking to them" },
        { value: "plc_fault", label: "A controller on 172.16.30.0/24 rebooted and re-registered with its peers, and that re-registration burst is what the sensors recorded as anomalous" },
        { value: "sensor_gap", label: "The passive sensor briefly lost its span-port feed, so the gap and the replayed Modbus records afterwards are themselves the reported incident" },
        { value: "new_plc", label: "A new controller was commissioned on the line, and its first Modbus handshakes with the engineering station are what opened the case overnight" },
      ],
      answer: "it_ot_cross",
      xp: 60,
      explanation:
        "The origin is the crossing. Zeek's conn.log shows 10.20.8.44, a corporate-VLAN address, opening Modbus/TCP 502 to 172.16.30.11, a controller on the production VLAN it has no prior history with, and the IT/OT boundary firewall shows the session being allowed. A 10.x host speaking an industrial protocol to a 172.16.x PLC is the IT→OT boundary being crossed by something that does not belong on that segment (T0886). Everything downstream (the address sweep, the writes) follows from it. (b), (c) and (d) invent benign explanations the records do not support, there is no reboot, no span-port gap, and no commissioning handshake; there is a foreign host issuing Modbus to controllers it never contacted.",
    },
    {
      id: "q2",
      prompt:
        "The authorized station and the corporate host both send Modbus/TCP to PLC-LINE1-01. Which field, above all others, proves the corporate host issued a WRITE to the controller rather than the read-only polling the engineering station does?",
      hint: "Zeek decodes the Modbus payload. Compare that one decoded field between the two sources.",
      kind: "single",
      options: [
        { value: "func_code", label: "zeek.modbus.func, WRITE_SINGLE_REGISTER and WRITE_MULTIPLE_REGISTERS from 10.20.8.44, READ_HOLDING_REGISTERS from the station" },
        { value: "dst_port", label: "id.resp_p 502 on the controller, the Modbus command port, which a read-only polling station has no need to open" },
        { value: "byte_count", label: "orig_bytes on the corporate host's sessions, writes carry register payloads, so more bytes than the polling marks a write" },
        { value: "conn_state", label: "conn_state SF on the corporate host's sessions versus REJ on the polling, Zeek's marker of a Modbus command being accepted" },
      ],
      answer: "func_code",
      xp: 70,
      explanation:
        "It is the decoded Modbus function code. Zeek's protocol decode records zeek.modbus.func: for 10.20.8.44 it is WRITE_SINGLE_REGISTER (function 6) and WRITE_MULTIPLE_REGISTERS (function 16); for the engineering station 172.16.30.5 it is READ_HOLDING_REGISTERS. Read the source IP alongside it and the picture is complete, a write, from a host that is not the sanctioned station; the controller's RESPONSE records carry no exception, and the station's next poll shows the changed value. (b) is wrong: both reads and writes use port 502, so the port distinguishes nothing. (c) over-reads volume, byte counts vary with register quantity and prove nothing about direction. (d) misreads a field: SF just means the TCP session opened and closed cleanly (it applies equally to the benign reads); it says nothing about read vs write.",
    },
    {
      id: "q3",
      prompt:
        "ENG-HMI-01 (172.16.30.5) sends Modbus to the very same controllers, continuously, including during the incident. Why is that traffic NOT the incident, while 10.20.8.44's is?",
      hint: "Two things separate them: who the source is, and what the source asks the controller to do.",
      kind: "single",
      options: [
        { value: "identity_and_read", label: "It is the sanctioned operator host inside the OT range and only READS registers for display, unlike the foreign host that WROTE" },
        { value: "hmi_offline", label: "ENG-HMI-01 was offline during the incident window, so none of its polling overlaps the malicious session and there is nothing to separate" },
        { value: "different_plc", label: "The engineering station polls a separate controller on the line, so it does not touch PLC-LINE1-01 and there is no overlap to compare" },
        { value: "encrypted", label: "The station's Modbus runs over TLS on port 802 while the corporate host's is plaintext on 502, and only a plaintext session can carry a write" },
      ],
      answer: "identity_and_read",
      xp: 60,
      explanation:
        "Same protocol, same port, same PLCs, the discriminators are source identity and function code. 172.16.30.5 is the plant's authorized operator/engineering station, it lives inside the OT range, and its sessions are READ_HOLDING_REGISTERS: it is reading live values to display them, which is its whole job. 10.20.8.44 is a corporate host that crossed the boundary and issued WRITE function codes. (b) is false, the station polls before, during and after the incident (evt_ot_00b, 00c, 00d), shown precisely so you can compare. (c) is false, both sources reach PLC-LINE1-01. (d) is false and technically confused: standard Modbus/TCP is plaintext for both, and encryption has nothing to do with read vs write.",
    },
    {
      id: "q4",
      prompt:
        "Before the writes, 10.20.8.44 opened a run of brief Modbus/TCP connections to 172.16.30.11, .12 and .13 within seconds. What is that activity, in ATT&CK-for-ICS terms?",
      hint: "Short, low-byte sessions to a range of addresses, back to back, what is the source trying to learn?",
      kind: "single",
      options: [
        { value: "discovery", label: "Remote System Discovery, the host probes a range of controller addresses to map which units answer and what they expose, before acting" },
        { value: "beacon", label: "Command-and-control beaconing, the evenly spaced short sessions are check-ins to an external controller node asking for its next instructions" },
        { value: "backup", label: "A scheduled configuration backup pulling each controller's program in turn, which typically produces exactly this burst of short connections" },
        { value: "failover", label: "Redundancy failover between controllers, where the run of short sessions is the line handing control over to its standby units one by one" },
      ],
      answer: "discovery",
      xp: 55,
      explanation:
        "That burst is device/point discovery, Remote System Discovery (T0846). Short, low-byte Modbus sessions swept across 172.16.30.11-13 in seconds, with a device-identification probe to .12 and .13, are the host asking each controller which units respond, building a map before it writes; the origin workstation's Python script was started with exactly that range as its arguments. (b) is wrong: this is inbound enumeration of the local controller range, not periodic outbound check-ins to an external node. (c) misattributes it, a configuration backup comes from the engineering station over its normal tooling, not from a corporate host mid-intrusion, and would not be paired with register writes minutes later. (d) invents a failover the records do not show; failover is controller-to-controller, not a corporate host sweeping the range.",
    },
    {
      id: "q5",
      prompt:
        "You have confirmed the writes. There is no EDR to isolate the PLC, and the controller drives a physical process. What response fits the evidence and the environment?",
      hint: "Think about where you CAN cut the traffic, and who has to verify the physical side, not what you would do to an ordinary workstation.",
      kind: "single",
      options: [
        { value: "boundary_and_engineers", label: "Cut the host off at the IT/OT boundary and isolate it with its EDR, then have process engineers check the written registers against intended values and revert safely" },
        { value: "isolate_plc_edr", label: "Push an EDR network-isolation action to PLC-LINE1-01 to quarantine the controller, the same containment used for a compromised laptop" },
        { value: "reboot_plc", label: "Power-cycle the controller remotely right away to flush the written registers, and close the incident once the line resumes normal production" },
        { value: "block_502_all", label: "Block every TCP 502 flow across the site at once, which halts the writes immediately without waiting on operations or engineering" },
      ],
      answer: "boundary_and_engineers",
      xp: 65,
      explanation:
        "OT containment is not workstation containment. You cannot put an agent on a PLC, so you cut the crossing where you can, at the IT/OT boundary (the firewall rule that allowed 10.20.8.44 to reach 172.16.30.11) and on the corporate workstation itself, which does run an EDR and can be isolated, and you engage the process engineers to compare the affected registers against their intended values (the setpoint read 1500 before the write) and revert safely, because a write can have moved the physical process. (b) is impossible: a PLC runs no EDR sensor, so there is no isolation action to push. (c) is dangerous, blindly rebooting a live controller can itself disrupt the process and destroys volatile evidence, and it does nothing about the source. (d) breaks the plant: killing all 502 also kills the legitimate engineering polling that keeps operators blind to the line, and it must be coordinated with operations, not done unilaterally.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Suricata ICS alert for a production line PLC",
    threat_actor: "IT-to-OT pivot operator issuing industrial-protocol commands from a corporate foothold",
    attack_kind: "ot_ics_intrusion",
    briefing:
      "A Suricata ICS alert fired at 22:13 for traffic to plc-line1-01. Work out who sent it, what it did to the controller and how to scope a response where the plant side has no endpoint agent.",
    narrative: `This case lives on the network. The plant floor has no endpoint agents, you cannot install EDR on a programmable logic controller, so the plant-side witnesses are two passive sensors: a Corelight (Zeek) sensor that reconstructs connections and decodes the Modbus/TCP protocol, and a Suricata IDS with ICS-aware signatures. The corporate end of the crossing is ordinary IT: the IT/OT boundary firewall and an EDR on the workstation.

At 22:08:30 PowerShell started on WKS-NEXA-044 (10.20.8.44), a corporate workstation, and at 22:09:48 a Python script, mbtool.py, started from it with the controller range 172.16.30.11-13 and port 502 as arguments. At 22:10 the boundary firewall allowed 10.20.8.44 to 172.16.30.11 on port 502 (app modbus), and Zeek's connection log recorded the Modbus/TCP session to plc-line1-01 (172.16.30.11) on the production VLAN, with a first READ_HOLDING_REGISTERS message. That is the origin of the whole case: a host from the business network reaching a controller it has no history with, across the IT/OT boundary. Within seconds it opened short, low-byte connections to .12 and .13, each probing which units answered with a device-identification message. That address sweep is device/point discovery, and Suricata's ICS ruleset fired on a Modbus client enumerating the segment from outside the engineering address block.

At 22:12:30 the host read the holding register at offset 7 (40008) and the controller answered 1500. At 22:13:00 a new session opened and Zeek decoded a Modbus WRITE_SINGLE_REGISTER (function code 6) setting that register to 0, with a response and no exception; the engineering station's next poll, seven seconds later, showed the value 0. Twenty seconds after the first write came a WRITE_MULTIPLE_REGISTERS (function code 16) writing four holding registers from offset 9 (40010). A write to a controller is not a lookup, it changes a value the physical process runs on. Suricata raised its high-severity detection on the write function code from a non-engineering source, and that alert opened the incident.

The one legitimate comparison is eng-hmi-01 (172.16.30.5), the plant's authorized operator station, polling the very same controllers all day with Modbus READ_HOLDING_REGISTERS, before, during and after the intrusion. Same protocol, same port, same PLCs, opposite verdict. The tells are the source identity (an OT-resident engineering host versus a corporate host that crossed the boundary) and, decisively, the decoded Modbus function code: a read that displays a value versus a write that sets one.

Because there is no agent on the PLC, containment is an OT problem, not a workstation one: cut the offending host at the IT/OT boundary and isolate it with its EDR, and bring in the process engineers to check the written registers against their intended values and revert safely, never blindly reboot a live controller or blanket-block 502, which would blind the legitimate engineering polling too.`,
    learning_objectives: [
      "Investigate an OT/ICS incident whose plant side has network-only telemetry (Corelight/Zeek connection and Modbus decode, Suricata ICS signatures) because there are no endpoint agents on controllers, and pivot to the corporate origin host and the boundary firewall",
      "Recognise an IT→OT crossing as the origin: a corporate-VLAN host speaking an industrial protocol to controllers it has no history with (T0886)",
      "Read a Modbus decode to tell a register WRITE (function 6/16) apart from read-only polling (READ_HOLDING_REGISTERS), and treat a write to a controller as impact (T0836/T0855)",
      "Distinguish the authorized engineering station's legitimate polling from a foreign host's traffic using source identity and function code, not the protocol or port",
      "Scope OT containment appropriately, cut the crossing at the IT/OT boundary, isolate the corporate origin host, and involve process engineers to verify and revert controller values, rather than applying workstation-style isolation to a PLC",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-28T14:03:07.000Z", phase: "Baseline", action: `${engHmi.host} (${engHmi.ip}) polls ${plc1.host} with Modbus READ_HOLDING_REGISTERS, the authorized station's routine` },
      { ts: T(-90 * SEC), phase: "Execution", action: `PowerShell, then a Python script with the controller range as arguments, starts on ${origin.hostname} (${attackerIp})` },
      { ts: T(0), phase: "Lateral Movement", action: `${attackerIp} (corporate VLAN) opens Modbus/TCP 502 to ${plc1.host} (${plc1.ip}) through the IT/OT boundary firewall, IT→OT crossing (T0886)` },
      { ts: T(40 * SEC), phase: "Discovery", action: `${attackerIp} sweeps controllers 172.16.30.11-13 with short Modbus probes, point/device discovery (T0846)` },
      { ts: T(52 * SEC), phase: "Discovery", action: "Suricata ICS signature fires on Modbus enumeration from a non-engineering source" },
      { ts: T(2 * MIN + 30 * SEC), phase: "Collection", action: `${attackerIp} reads register 40008 (offset 7) on ${plc1.host}: 1500, the before-value (T0801)` },
      { ts: T(3 * MIN), phase: "Impair Process Control", action: `Modbus WRITE_SINGLE_REGISTER (fc 6) ${attackerIp} → ${plc1.ip} register 40008 set to 0 (T0836)` },
      { ts: T(3 * MIN + 20 * SEC), phase: "Impair Process Control", action: `Modbus WRITE_MULTIPLE_REGISTERS (fc 16) ${attackerIp} → ${plc1.ip} block @40010 (T0855)` },
      { ts: T(3 * MIN + 30 * SEC), phase: "Detection", action: "Suricata raises the high-severity ICS detection on the write function code from outside the engineering block" },
    ],
    questions,
  };
}
