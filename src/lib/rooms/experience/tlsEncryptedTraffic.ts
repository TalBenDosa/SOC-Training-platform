import type { BriefingLab, RoomExperience } from "./types";

// "Operation Sealed Room" for the "tls-encrypted-traffic" room.
// Script: docs/campaign/75-tls-encrypted-traffic.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// NEW TASK ORDER (the room's own order keeps all six readings first, so it cannot be staged):
// tls-r1, tls-o1, tls-r2, tls-q1 | tls-r3, tls-r6, tls-la2 | tls-r4, tls-q2, tls-la1, tls-f1, tls-qf1 |
// tls-r5, tls-q3, tls-m1 | tls-ac1
// o1 follows r1 because it orders the handshake r1 teaches; la2 needs certificate age (r2) and JARM
// (r3); q2 weighs signals only r4 teaches; f1 and qf1 both say they follow Log Analysis 1; m1 needs
// pinning, so it follows r5; ac1 is the boss.
//
// Tessellate Payments (fictional card processor), not the graded tasks' solvix records.
// Signature: Read What Encryption Leaves. A capture where SNI, certificate fields and JA3 and JA4
// are visible while every payload is empty, and a tune lab on beacon timing and certificate age
// that separates C2 from telemetry. You can't read the letter, but you can read the envelope.
// Game mix: codebreak + intercept + tune.
// Lab data differs from the graded tasks: the capture reads one shared IP with two sites and never
// asks for the handshake order or a round-trip count (r1 checkpoint, o1, q1); the certificate age
// drill is a ten-year self-signed certificate three days old, never a one-year one about a day old
// (r2 checkpoint, la2); the first-contact queue is a gateway, a jump host and a reporting server on
// 9443 and 443, never a build server on 8443 (la2); the laptop's beacon is five minutes on
// sync.ledgerfont.example at 203.0.113.118, never a 60-second one on 198.51.100.201, and negotiates
// ECDHE AES-256-GCM, never RSA AES-128-CBC (la1, f1); the rule drill uses port 9443, a floor of 200
// and a ceiling of 40, outside every graded blank (qf1); the failing app is tokenvault.exe in a
// treasury team and it shows why one failing app differs from a dead proxy CA (q3); the boss
// drill's benign case is a sanctioned scanner touching an expired certificate in its booked window,
// never an internal appliance with a self-signed certificate on a schedule (ac1).

type Lab<K extends BriefingLab["kind"]> = Extract<BriefingLab, { kind: K }>;
type Packet = Lab<"pcap">["packets"][number];

const LT = "10.72.20.46";
const SHARED = "198.51.100.21";
const EDGE = "198.51.100.40";
const FRONT = "198.51.100.77";
const SILENT = "203.0.113.118";
const SILENT_NAME = "sync.ledgerfont.example";
const BROWSER_JA4 = "t13d1516h2_a1f4c07e2b91_7c3de0915fa4";
const THIN_JA4 = "t12d060500_5e0c9b7a14d2_c8a3f1620be7";
const THIN_JA3 = "e5f13a7c0b9d4286a1c7d36e4f08b251";

function ip(src: string, dst: string, sport: number, dport: number) {
  return [`Internet Protocol Version 4, Src: ${src}, Dst: ${dst}`, `Transmission Control Protocol, Src Port: ${sport}, Dst Port: ${dport}`];
}
function tcp(no: number, time: string, src: string, dst: string, len: number, info: string, sport: number, dport: number): Packet {
  return { no, time, src, dst, proto: "TCP", len, info, tree: ip(src, dst, sport, dport) };
}
function tls(no: number, time: string, src: string, dst: string, proto: string, len: number, info: string, sport: number, dport: number, lines: string[]): Packet {
  return { no, time, src, dst, proto, len, info, tree: [...ip(src, dst, sport, dport), "Transport Layer Security", ...lines] };
}
/** Application data: nothing but the record header, which is the whole point. */
const sealed = (ver: string) => [`${ver} Record Layer: Application Data Protocol: Application Data`, "Encrypted Application Data: [sealed, no key on this sensor]"];

const browserHello = (rec: string, sni: string, ja3: string, extra: string[] = []) => [
  `${rec} Record Layer: Handshake Protocol: Client Hello`,
  "Handshake Protocol: Client Hello",
  "Version: TLS 1.2 (0x0303)",
  "Cipher Suites (16 suites)",
  "Cipher Suite: Reserved (GREASE) (0x1a1a)",
  "Extension: Reserved (GREASE) (len=0)",
  `Extension: server_name (len=${sni.length + 5}) name=${sni}`,
  "Extension: application_layer_protocol_negotiation (len=14) ALPN: h2, http/1.1",
  "Extension: supported_versions (len=7) TLS 1.3, TLS 1.2",
  "Extension: key_share (len=43) x25519",
  ...extra,
  `[JA4: ${BROWSER_JA4}]`,
  `[JA3: ${ja3}]`,
];
const thinHello = [
  "TLSv1.2 Record Layer: Handshake Protocol: Client Hello",
  "Handshake Protocol: Client Hello",
  "Version: TLS 1.2 (0x0303)",
  "Cipher Suites (6 suites)",
  `Extension: server_name (len=${SILENT_NAME.length + 5}) name=${SILENT_NAME}`,
  "Extension: supported_groups (len=8)",
  "Extension: ec_point_formats (len=2)",
  "Extension: signature_algorithms (len=20)",
  "Extension: extended_master_secret (len=0)",
  `[JA4: ${THIN_JA4}]`,
  `[JA3: ${THIN_JA3}]`,
];
const hello12 = (cipher: string, ja3s: string, ja4s: string) => [
  "TLSv1.2 Record Layer: Handshake Protocol: Server Hello",
  "Handshake Protocol: Server Hello",
  "Version: TLS 1.2 (0x0303)",
  `Cipher Suite: ${cipher}`,
  `[JA4S: ${ja4s}]`,
  `[JA3S: ${ja3s}]`,
];
const certFlight = (cert: string[]) => [
  "TLSv1.2 Record Layer: Handshake Protocol: Certificate",
  ...cert,
  "TLSv1.2 Record Layer: Handshake Protocol: Server Key Exchange",
  "EC Diffie-Hellman Server Params: Curve x25519",
  "TLSv1.2 Record Layer: Handshake Protocol: Server Hello Done",
];
const clientFinish = ["TLSv1.2 Record Layer: Handshake Protocol: Client Key Exchange", "TLSv1.2 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec", "TLSv1.2 Record Layer: Handshake Protocol: Encrypted Handshake Message", "[The encrypted message is the client's Finished]"];
const serverFinish = ["TLSv1.2 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec", "TLSv1.2 Record Layer: Handshake Protocol: Encrypted Handshake Message", "[The encrypted message is the server's Finished]"];
const CKE = "Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message";
const SKE = "Certificate, Server Key Exchange, Server Hello Done";
const CCS = "Change Cipher Spec, Encrypted Handshake Message";
const AD = "Application Data";
const FLIGHT13 = "Server Hello, Change Cipher Spec, Application Data, Application Data";
const hello13 = (cipher: string) => [
  "TLSv1.3 Record Layer: Handshake Protocol: Server Hello",
  "Handshake Protocol: Server Hello",
  "Version: TLS 1.2 (0x0303)",
  `Cipher Suite: ${cipher}`,
  "Extension: supported_versions (len=2) TLS 1.3",
  "Extension: key_share (len=36) x25519",
  "TLSv1.3 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec",
  "TLSv1.3 Record Layer: Application Data Protocol: Application Data",
  "TLSv1.3 Record Layer: Application Data Protocol: Application Data",
  "[Everything after the Server Hello is encrypted, the certificate included]",
];

const SILENT_CERT = [
  `Certificates (1 cert): subject: id-at-commonName=${SILENT_NAME}`,
  `    issuer: id-at-commonName=${SILENT_NAME}`,
  "    serialNumber: 0x4f1c7ea2",
  "    validity: notBefore 2026-10-30 22:05:11 UTC, notAfter 2036-10-27 22:05:11 UTC",
];
const silentSession = (first: number, base: number, port: number): Packet[] => {
  const t = (d: number) => (base + d).toFixed(6);
  return [
    tls(first, t(0), LT, SILENT, "TLSv1.2", 214, `Client Hello (SNI=${SILENT_NAME})`, port, 443, thinHello),
    tls(first + 1, t(0.0312), SILENT, LT, "TLSv1.2", 133, "Server Hello", 443, port, hello12("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)", "b7d20e1f9a6c43580ce1f7a2d9346c18", "t120300_c030_6d1e04b7c2fa")),
    tls(first + 2, t(0.0319), SILENT, LT, "TLSv1.2", 1012, SKE, 443, port, certFlight(SILENT_CERT)),
    tls(first + 3, t(0.0634), LT, SILENT, "TLSv1.2", 171, CKE, port, 443, clientFinish),
    tls(first + 4, t(0.0941), SILENT, LT, "TLSv1.2", 105, CCS, 443, port, serverFinish),
    tls(first + 5, t(0.0957), LT, SILENT, "TLSv1.2", 478, AD, port, 443, sealed("TLSv1.2")),
    tls(first + 6, t(0.1266), SILENT, LT, "TLSv1.2", 301, AD, 443, port, sealed("TLSv1.2")),
  ];
};

const CAPTURE: Packet[] = [
  // Session 1: TLS 1.2 to a shared address.
  tcp(1, "0.000000", LT, SHARED, 66, "50114 > 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460", 50114, 443),
  tcp(2, "0.018204", SHARED, LT, 66, "443 > 50114 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460", 443, 50114),
  tcp(3, "0.018391", LT, SHARED, 54, "50114 > 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0", 50114, 443),
  tls(4, "0.018702", LT, SHARED, "TLSv1.2", 571, "Client Hello (SNI=portal.clearhouse-net.example)", 50114, 443, browserHello("TLSv1.2", "portal.clearhouse-net.example", "4b1e9c0a7d3f52e6881c6a07f3d2b914")),
  tls(5, "0.037120", SHARED, LT, "TLSv1.2", 139, "Server Hello", 443, 50114, hello12("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)", "2c91f06ad7e8b3415f0a7ce1d6438b90", "t1204h2_c02f_91ae02c7d5b3")),
  tls(6, "0.037644", SHARED, LT, "TLSv1.2", 1418, SKE, 443, 50114, certFlight([
    "Certificates (2 certs): subject: id-at-commonName=portal.clearhouse-net.example",
    "    issuer: id-at-commonName=Northgate TLS CA 7, id-at-organizationName=Northgate Trust",
    "    validity: notBefore 2026-09-21 00:00:00 UTC, notAfter 2026-12-20 23:59:59 UTC",
    "    Extension (id-ce-subjectAltName): dNSName: portal.clearhouse-net.example",
    "  Second certificate: subject: id-at-commonName=Northgate TLS CA 7",
    "    issuer: id-at-commonName=Northgate Root R2",
  ])),
  tls(7, "0.056118", LT, SHARED, "TLSv1.2", 180, CKE, 50114, 443, clientFinish),
  tls(8, "0.074502", SHARED, LT, "TLSv1.2", 105, CCS, 443, 50114, serverFinish),
  tls(9, "0.075330", LT, SHARED, "TLSv1.2", 1242, AD, 50114, 443, sealed("TLSv1.2")),
  tls(10, "0.112871", SHARED, LT, "TLSv1.2", 1514, AD, 443, 50114, sealed("TLSv1.2")),
  // Session 2: the same address, another site, another certificate.
  tls(11, "6.402118", LT, SHARED, "TLSv1.2", 563, "Client Hello (SNI=board.merchantdesk.example)", 50119, 443, browserHello("TLSv1.2", "board.merchantdesk.example", "0e7fa35bd1c8246a9b1f40de7c6538a2")),
  tls(12, "6.420733", SHARED, LT, "TLSv1.2", 139, "Server Hello", 443, 50119, hello12("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)", "2c91f06ad7e8b3415f0a7ce1d6438b90", "t1204h2_c02f_91ae02c7d5b3")),
  tls(13, "6.421204", SHARED, LT, "TLSv1.2", 1396, SKE, 443, 50119, certFlight([
    "Certificates (2 certs): subject: id-at-commonName=board.merchantdesk.example",
    "    issuer: id-at-commonName=Northgate TLS CA 7, id-at-organizationName=Northgate Trust",
    "    validity: notBefore 2026-10-05 00:00:00 UTC, notAfter 2027-01-03 23:59:59 UTC",
    "    Extension (id-ce-subjectAltName): dNSName: board.merchantdesk.example",
  ])),
  tls(14, "6.439518", LT, SHARED, "TLSv1.2", 180, CKE, 50119, 443, clientFinish),
  tls(15, "6.457920", SHARED, LT, "TLSv1.2", 105, CCS, 443, 50119, serverFinish),
  tls(16, "6.458807", LT, SHARED, "TLSv1.2", 987, AD, 50119, 443, sealed("TLSv1.2")),
  // Session 3: TLS 1.3, where the certificate disappears from view.
  tls(17, "14.220541", LT, EDGE, "TLSv1.3", 583, "Client Hello (SNI=docs.tilepartners.example)", 50127, 443, browserHello("TLSv1.3", "docs.tilepartners.example", "c92d7e4410ab36f1de0578b2a6c1f30e", ["[TLS 1.3: the client's key share is already in this first message]"])),
  tls(18, "14.238804", EDGE, LT, "TLSv1.3", 1514, FLIGHT13, 443, 50127, hello13("TLS_AES_128_GCM_SHA256 (0x1301)")),
  tls(19, "14.241920", LT, EDGE, "TLSv1.3", 134, "Change Cipher Spec, Application Data", 50127, 443, ["TLSv1.3 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec", ...sealed("TLSv1.3")]),
  tls(20, "14.242377", LT, EDGE, "TLSv1.3", 1034, AD, 50127, 443, sealed("TLSv1.3")),
  tls(21, "14.279113", EDGE, LT, "TLSv1.3", 1514, AD, 443, 50127, sealed("TLSv1.3")),
  // Session 4: ECH.
  tls(22, "23.611090", LT, FRONT, "TLSv1.3", 612, "Client Hello (SNI=public.edgefront.example)", 50133, 443, browserHello("TLSv1.3", "public.edgefront.example", "71d3a0e6c25f84b9e07c1fd2b64a93e8", ["Extension: encrypted_client_hello (len=218) Client Hello type: Outer", "[The real Client Hello, with the real site name, is sealed inside this extension]"])),
  tls(23, "23.629477", FRONT, LT, "TLSv1.3", 1514, FLIGHT13, 443, 50133, hello13("TLS_AES_128_GCM_SHA256 (0x1301)")),
  tls(24, "23.632015", LT, FRONT, "TLSv1.3", 134, "Change Cipher Spec, Application Data", 50133, 443, ["TLSv1.3 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec", ...sealed("TLSv1.3")]),
  tls(25, "23.632602", LT, FRONT, "TLSv1.3", 842, AD, 50133, 443, sealed("TLSv1.3")),
  // Sessions 5 and 6: one thin client, 302 seconds apart, matching the conn.log rows in tls-r4.
  ...silentSession(26, 41.208114, 50141),
  ...silentSession(33, 343.208402, 50188),
];

export const TLS_ENCRYPTED_TRAFFIC: RoomExperience = {
  roomId: "tls-encrypted-traffic",
  codename: "Operation Sealed Room",
  theme: "sealedroom",
  handler: { name: "Ruaridh Banerjee", role: "Network Security Analyst, Tessellate Payments" },
  briefing: [
    "Tessellate Payments. Merchant payouts for half a continent, and one locked floor where Friday's settlement run is built.",
    "Everything leaving that floor is TLS, and by policy nobody decrypts it. Inside the building they call it the Sealed Room.",
    "This week a laptop on the floor started keeping a schedule nobody gave it, and Ruaridh Banerjee can't read one byte of what it sends.",
    "You can't read the letter, but you can read the envelope. Learn what encryption leaves behind, and make the call before Friday.",
  ],
  mission: "Read two handshakes in a capture with every payload sealed, walk a certificate chain, fingerprint a client from its hello, work a first-contact queue, tune a rule on rhythm and certificate age, trace a check-in to its process, find where the proxy stops seeing, then rule on the last alert of the shift.",
  estimate: "~75 min",
  look: { primary: "#e07a5f", secondary: "#a8dadc", warn: "#ffd166" },
  scene: "facilitysealedroom",
  layout: "facility",
  stations: [
    {
      id: "handshake",
      label: "The Handshake",
      topic: "TLS 1.2 and 1.3 message by message · SNI and ECH · certificate chains · self-signed and short-lived certificates",
      tagline: "What crosses before the seal?",
      building: "control",
      taskIds: ["tls-r1", "tls-o1", "tls-r2", "tls-q1"],
    },
    {
      id: "fingerprint",
      label: "The Fingerprint",
      topic: "JA3, JA3S, JARM and JA4 · browser and bare-bones hellos · legacy TLS · first contact",
      tagline: "The hello gives the sender away",
      building: "lab",
      taskIds: ["tls-r3", "tls-r6", "tls-la2"],
    },
    {
      id: "beacon",
      label: "The Beacon",
      topic: "Beacon timing and jitter · byte consistency · rarity · SNI against hosting · building a case from metadata",
      tagline: "It keeps a schedule nobody gave it",
      building: "office",
      taskIds: ["tls-r4", "tls-q2", "tls-la1", "tls-f1", "tls-qf1"],
    },
    {
      id: "proxy",
      label: "The Proxy",
      topic: "How TLS interception works · where it stops · excluded categories and unmanaged devices",
      tagline: "Why not just open it?",
      building: "vault",
      taskIds: ["tls-r5", "tls-q3", "tls-m1"],
    },
    {
      id: "sealedroom",
      label: "The Sealed Room",
      topic: "Reading age, rarity, recurrence and owner into one verdict",
      tagline: "Read the values behind the flag",
      building: "ticket",
      taskIds: ["tls-ac1"],
      boss: true,
    },
  ],
  personas: {
    "tls-o1": { name: "Ruaridh Banerjee", role: "Network Security Analyst", line: "Put the messages in the order they crossed the wire." },
    "tls-q1": { name: "Ruaridh Banerjee", role: "Network Security Analyst", line: "The firewall team asked me something simple this morning. Help me answer it." },
    "tls-la2": { name: "Ruaridh Banerjee", role: "Network Security Analyst", line: "One session, one new destination. Walk me through it." },
    "tls-q2": { name: "Ruaridh Banerjee", role: "Network Security Analyst", line: "Four findings from one workstation. Weigh them for me." },
    "tls-la1": { name: "Ruaridh Banerjee", role: "Network Security Analyst", line: "The anomaly rule raised this one. Read the record before you read the rule." },
    "tls-f1": { name: "Ruaridh Banerjee", role: "Network Security Analyst", line: "Give me one field, exactly as the sensor wrote it." },
    "tls-qf1": { name: "Ruaridh Banerjee", role: "Network Security Analyst", line: "Make it something that runs across the whole network." },
    "tls-q3": { name: "Ruaridh Banerjee", role: "Network Security Analyst", line: "One application keeps failing at the inspection point. What am I looking at?" },
    "tls-m1": { name: "Ruaridh Banerjee", role: "Network Security Analyst", line: "Before the last alert, get the terms straight." },
    "tls-ac1": { name: "Ruaridh Banerjee", role: "Network Security Analyst", line: "Last alert of the shift, and the run starts at six. Your call." },
  },
  briefings: {
    // ── Reading 1: the handshake ──
    "tls-r1": [
      {
        kind: "pcap",
        title: "Read the Envelope: Six Sealed Sessions",
        prompt: "Monday 2 November, 09:13. Ruaridh mirrored one laptop's traffic on the settlement floor for six minutes, and no key on this sensor opens any of it. Filter, pick a packet, and read its layers. Watch the right-hand pane stay empty while the left one keeps talking. Sessions after the first are trimmed to start at the hello.",
        capture: "tp-settlement-span_mon0913.pcapng",
        primer: {
          fold: true,
          title: "How to read a TLS handshake in a capture",
          points: [
            "TLS (Transport Layer Security) opens with a **Client Hello** and a **Server Hello**, sent before any key exists. Anyone on the path can read them. That is the envelope.",
            "**SNI** (Server Name Indication) is an extension in the Client Hello that names the site the client wants.",
            "In **TLS 1.2** the certificate crosses in the clear: subject, issuer, validity dates and **SAN** (Subject Alternative Name, the hostnames it covers). In **TLS 1.3** it is encrypted, so a sensor sees the hellos and then `Application Data`. 1.3 needs one round trip, because the Client Hello already carries a `key_share`.",
            "**ECH** (Encrypted Client Hello) seals the real Client Hello inside an outer one. The outer SNI names only the shared front end.",
            "**JA4** is a fingerprint your analyser computes from the Client Hello, not something the client sends. Its first block reads left to right: `t` for TCP, TLS version, `d` if SNI is present or `i` if not, cipher count, extension count, first ALPN (Application-Layer Protocol Negotiation) value, `00` for none.",
          ],
          example: {
            label: "One Client Hello from another network, read top to bottom",
            lines: [
              "`Extension: server_name name=mirror.fabric-cdn.example`: the site asked for",
              "`[JA4: t13d1715h2_...]`: TCP, TLS 1.3, SNI present, 17 ciphers, 15 extensions, ALPN h2",
              "Next packets say `Application Data`: sealed. Only time, length and addresses remain",
            ],
          },
        },
        packets: CAPTURE,
        objectives: [
          { id: "sni", task: "Packet 4 opens session 1. Which hostname did the laptop name in its Client Hello?", hint: "\"client hello\"", answer: ["portal.clearhouse-net.example"], why: "That is SNI, readable on the wire even though nothing has been encrypted yet, and nothing can be: no keys exist at this point. It's the field most firewalls and proxies use to categorise HTTPS without decrypting it." },
          { id: "issuer", task: "Packet 6 carries that server's certificate in the clear. Which CA (certificate authority) issued it?", hint: "ip.addr==198.51.100.21", answer: ["Northgate TLS CA 7", "Northgate", "Northgate Trust"], why: "In TLS 1.2 the whole chain crosses in the open: subject, issuer, dates and SAN. Reading the second certificate shows the chain climbing from the leaf to an intermediate and on towards a root. The messages after it carry key exchange, then each side's Finished." },
          { id: "cipher", task: "Which cipher suite did the server choose in packet 5?", hint: "\"server hello\"", answer: ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "0xc02f"], why: "The client offers a list and the server picks one. Sensors record this field exactly as named here, and it's a fast first read of how modern a stack is. ECDHE means ephemeral key exchange, which is why packet 6 also carries a Server Key Exchange." },
          { id: "shared", task: "Session 2 goes to the same IP address as session 1. Which site does the certificate in packet 13 name?", hint: "ip.addr==198.51.100.21", answer: ["board.merchantdesk.example"], why: "One address, two sites, two certificates. The server can't choose a certificate until it knows the site, and the client has to say so before any keys exist. That is why the name has to travel in the clear." },
          { id: "tls13", task: "Session 3 (packets 17 to 21) is TLS 1.3. How many of its packets show a certificate you can read?", hint: "ip.addr==198.51.100.40", answer: ["0", "zero", "none"], why: "None. The server's flight in packet 18 is a Server Hello and then opaque records, and the certificate is in there, encrypted. So on TLS 1.3 traffic a passive sensor has no subject, issuer or dates, and you need to fetch the certificate yourself or look it up. SNI is still in packet 17." },
          { id: "version", task: "Packet 17 says Version: TLS 1.2 in its Client Hello, yet the session is 1.3. Which extension really offers 1.3?", hint: "supported_versions", answer: ["supported_versions", "supported versions"], why: "The old version field is frozen at 1.2 so that middleboxes don't break. The true offer is in supported_versions, and the server's reply there settles it. Filters and parsers that read only the old field report 1.3 traffic as 1.2." },
          { id: "ech", task: "Session 4 uses ECH. Which name can your sensor still read in packet 22?", hint: "encrypted_client_hello", answer: ["public.edgefront.example"], why: "That is the outer name, and it belongs to the shared front end, not the site. The real SNI is inside the sealed extension. ECH isn't everywhere yet, but where it runs, the last cleartext field stops naming the destination, and you're left with the provider's address and name." },
          { id: "thin", task: "One client's JA4 first block ends in 00, so it offered no ALPN. Which hostname did it ask for?", hint: "t12d", answer: [SILENT_NAME], why: "t12d060500: TLS 1.2 at best, SNI present, 6 ciphers, 5 extensions, no ALPN. Compare the browser's t13d1516h2 on the same laptop. Two different pieces of software are talking from one machine, and you learned that without reading a byte of content." },
          { id: "age", task: "Read that server's certificate. How many days old was it on Monday 2 November?", hint: "ip.addr==203.0.113.118", answer: ["3", "three", "3 days", "three days"], why: "notBefore is 30 October. Issuer and subject are the same name, so it signed itself. The ten-year period means nothing: whoever generates a certificate picks any period they like. Age is the number that counts." },
          { id: "gap", task: "That client came back. How many whole seconds passed between its two Client Hellos?", hint: "t12d", answer: ["302", "302 seconds"], why: "302 seconds, close to five minutes, and packets 31 and 38 are the same length, as are 32 and 39. The content is sealed, and time and size aren't. Ruaridh has been staring at this laptop's rhythm all morning, and this room ends up back here." },
        ],
      },
      {
        kind: "sequence",
        title: "The TLS 1.3 Flight: Where the Seal Starts",
        prompt: "Packet 18 hid a lot inside one line. Ruaridh wants the TLS 1.3 handshake on the whiteboard for the new starter. Tap the messages in the order they happen, and watch the point where a sensor goes blind.",
        items: [
          { id: "cert", text: "Certificate and CertificateVerify", note: "Encrypted. This is what TLS 1.2 used to show." },
          { id: "app", text: "Application Data", note: "The HTTP request and response, sealed. Only time, length and addresses remain." },
          { id: "ch", text: "Client Hello with SNI and a key_share", note: "Cleartext. The client guesses the key exchange now, which saves a round trip." },
          { id: "cfin", text: "Client Finished", note: "Encrypted. The client proves it saw the same handshake." },
          { id: "ee", text: "EncryptedExtensions", note: "The first encrypted message. Everything from here is opaque to a passive sensor." },
          { id: "sh", text: "Server Hello with its key_share", note: "Cleartext, and the last cleartext message. Both sides can now derive keys." },
          { id: "sfin", text: "Server Finished", note: "Encrypted, and in the same flight as the certificate." },
        ],
        order: ["ch", "sh", "ee", "cert", "sfin", "cfin", "app"],
        doneNote: "The server's whole answer fits in one flight, because the key share came with the question. On a repeat visit, 0-RTT resumption lets a client send data in its first flight, and because that early data can be replayed, it's kept to requests that are safe to repeat. Against TLS 1.2 the seal starts much later, after the certificate has crossed in the open.",
      },
    ],
    // ── Reading 2: SNI, ECH, certificate chains ──
    "tls-r2": [
      {
        kind: "anatomy",
        title: "Anatomy of a Certificate Record",
        prompt: "Before you judge an odd certificate, read a healthy one. This is one of Tessellate's vendors in the sensor's certificate log, field by field.",
        source: "Zeek · x509.log · tp-core-tap01",
        fields: [
          { key: "certificate.subject", value: "CN=pay-api.merchantdesk.example", label: "Who it claims to be", note: "CN (Common Name) is the old place for the hostname. Modern browsers match on the SAN list instead." },
          { key: "san.dns", value: "pay-api.merchantdesk.example", label: "What it covers", note: "SAN, Subject Alternative Name. This must match the name in the client's SNI, or validation fails." },
          { key: "certificate.issuer", value: "CN=Northgate TLS CA 7,O=Northgate Trust", label: "Who signed it", note: "An intermediate CA. If this were identical to the subject, the certificate would be vouching for itself." },
          { key: "certificate.not_valid_before", value: "2026-10-12T00:00:00Z", label: "Issued", note: "Compare this with the day the destination first appeared on your network. That gap is the age that matters." },
          { key: "certificate.not_valid_after", value: "2027-01-10T23:59:59Z", label: "Expires", note: "A 90-day period, which is normal: free automated CAs issue them by the million, and since March 2026 public certificates are capped at 200 days, with lower caps scheduled." },
          { key: "certificate.serial", value: "04A1F7C26E90B3D5", label: "Serial", note: "This is what a revocation check looks up." },
          { key: "certificate.sig_alg", value: "sha256WithRSAEncryption" },
          { key: "basic_constraints.ca", value: "F", label: "Can it sign others?", note: "F means this is a leaf. A leaf that signs other certificates breaks the chain." },
        ],
        summary: "Validation walks a chain: the leaf was signed by an intermediate, the intermediate by a root, and the root is already in the device's trust store. It passes only if every signature checks, nothing has expired, a SAN entry matches the SNI, and nothing is revoked. Revocation is checked through a CRL (Certificate Revocation List) or OCSP (Online Certificate Status Protocol), and clients enforce that unevenly. A short period is no warning sign today. Read the issuer, the SAN and the age, not the length of the validity.",
      },
      {
        kind: "simulate",
        title: "Which Certificate Flags Mean Anything?",
        prompt: "The same checks, six certificates from Tessellate's network this month. The first three checks are what a client validates. The last is the analyst's question. Run each one and read what the combination is worth.",
        checks: [
          { name: "Trusted chain", question: "Does the chain end at a root in the trust store?" },
          { name: "Name match", question: "Does a SAN entry match the SNI?" },
          { name: "Inside its dates", question: "Is today between its validity dates?" },
          { name: "Settled", question: "Had it been in place a good while when this destination first appeared?" },
        ],
        scenarios: [
          {
            id: "norm", label: "A vendor portal, public CA, 90-day certificate", detail: "Renewed last week, destination in traffic for three years",
            results: ["pass", "pass", "pass", "pass"],
            why: ["A public CA, chain intact.", "The SAN lists the portal's name.", "Well inside its dates.", "The destination is three years old on your network. A renewal is a new certificate on an old relationship."],
            verdict: "Nothing to see. A certificate renewed last week isn't a young destination, and 90 days is the norm.",
          },
          {
            id: "print", label: "The printer fleet console on 10.72.9.12", detail: "Self-signed by the vendor at install, two years ago",
            results: ["fail", "pass", "pass", "pass"],
            why: ["Issuer equals subject, so no CA vouches for it.", "It names the console.", "It runs for years.", "It has sat unchanged since install."],
            verdict: "Self-signed and boring. Appliances, management pages and lab gear ship like this, which is why self-signed on its own is a weak signal. Find the owner and move on.",
          },
          {
            id: "moved", label: "A partner's API after a migration", detail: "Public CA, but the SAN still lists only the old hostname",
            results: ["pass", "fail", "pass", "pass"],
            why: ["A public CA, chain intact.", "The SNI asks for the new name and the SAN has only the old one.", "Inside its dates.", "The certificate has been in place for months."],
            verdict: "A mistake, not an attack. Clients will fail it. It's worth a ticket to the partner and little more.",
          },
          {
            id: "launch", label: "A new merchant microsite, launched this week", detail: "Free automated CA, certificate four days old, change ticket on file",
            results: ["pass", "pass", "pass", "fail"],
            why: ["A public CA, chain intact.", "The SAN matches.", "Inside its dates.", "Four days old at first sight. New sites need new certificates."],
            verdict: "Young, and fully explained. A public CA proves only that someone controls the domain, so age alone decides nothing. The ticket does the work here.",
          },
          {
            id: "fresh", label: "An unknown server, self-signed, three days old", detail: "A ten-year validity period, first seen this morning, one client",
            results: ["fail", "pass", "pass", "fail"],
            why: ["It signed itself.", "It names itself, so this check is free.", "Ten years is whatever its maker typed.", "Three days old when it first appeared here."],
            verdict: "This is the pair worth your time. Even a self-signed internal box usually gets one certificate at install and keeps it for years. Attackers mint certificates on demand and throw them away, and self-signed is the default of several C2 (command and control) frameworks. Each fact is weak alone. Together they aren't.",
          },
          {
            id: "lapsed", label: "An internal wiki whose certificate lapsed on Sunday", detail: "Internal CA, expired two days ago, 300 clients as usual",
            results: ["pass", "pass", "fail", "pass"],
            why: ["The internal CA is in every managed device's trust store.", "The SAN matches.", "Expired two days ago.", "Issued a year ago."],
            verdict: "Expired isn't suspicious on its own either. It's an operations ticket, and users are clicking through warnings until someone fixes it.",
          },
        ],
      },
      {
        kind: "codebreak",
        title: "Name It from the Envelope",
        prompt: "Ruaridh keeps a list of terms the new starter must know cold. Each clue is something you'd see on the job. Crack the term.",
        rounds: [
          { id: "san", clue: "A user reaches portal.example and gets a name warning, because this certificate field holds only old-portal.example.", answer: "SAN", why: "Subject Alternative Name. Browsers match the hostname against this list, not the CN." },
          { id: "ocsp", clue: "A client asks a CA's responder about one serial number and hears good, revoked or unknown. Many clients don't enforce it, and some CAs have retired it.", answer: "OCSP", why: "Online Certificate Status Protocol. Its older cousin is the CRL, a published list of every revoked serial." },
          { id: "ech", clue: "Your sensor shows public.edgefront.example for forty different destinations. Which extension sealed the real names?", answer: "ECH", why: "Encrypted Client Hello. The outer hello names the shared front end and the real SNI sits inside. It costs defenders the same way encrypted DNS does." },
          { id: "alpn", clue: "A Client Hello says h2, http/1.1. Browsers send this list, and thin stacks often leave it out.", answer: "ALPN", why: "Application-Layer Protocol Negotiation. It agrees on HTTP/2 inside the handshake, and it's the last part of JA4's first block." },
        ],
        lesson: "Most of what you'll use in this job sits in the first two messages. SNI and ALPN come from the client, SAN and the issuer come from the certificate, and ECH and TLS 1.3 are what take pieces of that view away.",
      },
    ],
    // ── Reading 3: fingerprints ──
    "tls-r3": [
      {
        kind: "anatomy",
        title: "Anatomy of an ssl.log Line",
        prompt: "This is the sensor's own summary of that thin client's session. Nobody decrypted anything to write it. Read what it adds up to.",
        source: "Zeek · ssl.log · tp-core-tap01",
        fields: [
          { key: "id.orig_h", value: LT, label: "Client", note: "A host, not a process. The network can't tell you which program this was." },
          { key: "id.resp_h", value: SILENT, label: "Server" },
          { key: "version", value: "TLSv12", label: "Negotiated version" },
          { key: "cipher", value: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", label: "Chosen cipher" },
          { key: "server_name", value: SILENT_NAME, label: "SNI" },
          { key: "next_protocol", value: "-", label: "ALPN result", note: "Empty, so no protocol was agreed in the hello." },
          { key: "subject", value: `CN=${SILENT_NAME}`, note: "On a TLS 1.3 session these certificate fields stay empty, because the sensor never saw it." },
          { key: "issuer", value: `CN=${SILENT_NAME}`, note: "The same as the subject." },
          { key: "validation_status", value: "self signed certificate", label: "Sensor's check" },
          { key: "ja3", value: THIN_JA3, label: "Client fingerprint", note: "JA3: an MD5 of the version, ciphers, extensions, curves and point formats, in the order offered." },
          { key: "ja3s", value: "b7d20e1f9a6c43580ce1f7a2d9346c18", label: "Server fingerprint", note: "JA3S: the same idea on the Server Hello, so it describes the server's stack. The pair is stronger than either." },
          { key: "ja4", value: THIN_JA4, label: "Sorted client fingerprint", note: "JA4 sorts ciphers and extensions before hashing, so shuffling them changes nothing. Its first block stays readable." },
          { key: "ja4s", value: "t120300_c030_6d1e04b7c2fa", label: "Server side of JA4", note: "c030 is the chosen cipher. JA4+ also covers HTTP (JA4H), certificates (JA4X) and TCP (JA4T), and Zeek and Suricata both support it." },
        ],
        summary: "Notice what isn't here: a JARM. JARM can't come from a passive sensor at any volume, because a scanner has to send a server ten crafted Client Hellos and hash how it answers. That also makes it the one that works on a server you've never talked to, by comparing it with published signatures for default C2 servers. Every fingerprint here names a TLS library and its settings, never an intention, so a match is somewhere to pivot from and a missing match proves nothing.",
      },
      {
        kind: "worksheet",
        title: "One Browser, Many JA3s",
        prompt: "A slice of Monday's ssl.log, trimmed to four columns. Rows 1 to 4 are one Edge build on two laptops. Work the questions and see which fingerprint survives what.",
        caption: "Zeek ssl.log · Monday 09:00 to 10:00",
        primer: {
          fold: true,
          title: "Why JA3 stopped working on browsers",
          points: [
            "JA3 hashes lists **in the order they appear** in the hello.",
            "Since early 2023 Chrome and every Chromium browser **shuffle their extension order** on each connection, so one unchanged browser now emits a different JA3 almost every time.",
            "JA4 **sorts** the lists first, so the shuffle doesn't change it.",
            "Old or fixed-order stacks don't shuffle. Much malware and many C2 defaults still give a stable JA3, so it stays useful there.",
            "A fingerprint belongs to a library. Two honest programs on one runtime share it, and that's normal.",
          ],
          example: {
            label: "Reading two rows from another network",
            lines: [
              "`ja3=91c2...  ja4=t13d1715h2_x`, then `ja3=07ae...  ja4=t13d1715h2_x`",
              "Different JA3, same JA4: one browser, shuffled. Not two clients",
            ],
          },
        },
        columns: ["id.orig_h", "server_name", "ja3 (first 8)", "ja4"],
        rows: [
          ["10.72.20.46", "portal.clearhouse-net.example", "4b1e9c0a", BROWSER_JA4],
          ["10.72.20.46", "board.merchantdesk.example", "0e7fa35b", BROWSER_JA4],
          ["10.72.20.46", "docs.tilepartners.example", "c92d7e44", BROWSER_JA4],
          ["10.72.20.61", "docs.tilepartners.example", "71d3a0e6", BROWSER_JA4],
          ["10.72.20.46", SILENT_NAME, "e5f13a7c", THIN_JA4],
          ["10.72.20.46", "img.ledgerfont-cdn.example", "e5f13a7c", THIN_JA4],
          ["10.72.20.46", "files.northquay-archive.example", "e5f13a7c", THIN_JA4],
          ["10.72.5.40", "reports.tessellatepay.example", "e5f13a7c", THIN_JA4],
        ],
        questions: [
          { id: "ja3", q: "How many different ja3 values do rows 1 to 4 show?", hint: "Count the third column for the first four rows.", answer: ["4", "four"], why: "One browser build, four hashes. That's the shuffle, and it's why a JA3 that never repeats is normal now." },
          { id: "ja4", q: "How many different ja4 values do those same rows show?", hint: "Now the fourth column.", answer: ["1", "one"], why: "Sorted before hashing, so one build gives one JA4. This is the format that groups modern browsers." },
          { id: "pivot", q: "Pivot on the thin client's ja4. How many different server_name values does it reach?", hint: "Rows 5 to 8.", answer: ["4", "four"], why: "The names and addresses can change while the library stays. That's why a fingerprint outlives a domain blocklist, and it's the pivot worth running." },
          { id: "proof", q: "Row 8 is Tessellate's own reporting server with the same fingerprint. Does that prove it's compromised? (yes/no)", hint: "What does a fingerprint actually identify?", answer: ["no", "n"], why: "It identifies a TLS library and its settings. A plain script on the same runtime gives the same hash. Row 8 is a lead to check against its known job, not a verdict." },
        ],
      },
      {
        kind: "sort",
        title: "Which Fingerprint for This Job?",
        prompt: "Eight requests landed on Ruaridh's desk this week. For each, choose the fingerprint that can actually do the job. Ask yourself two things: which side of the connection, and do you need traffic to have happened yet?",
        buckets: [
          { id: "ja3", label: "JA3" },
          { id: "ja3s", label: "JA3S" },
          { id: "ja4", label: "JA4" },
          { id: "jarm", label: "JARM" },
        ],
        items: [
          { id: "f1", text: "An old malware family has a hard-coded hello, and last year's archived logs stored only one MD5 per session.", bucket: "ja3", why: "A fixed-order stack still gives a stable JA3, and that's the only field those logs hold." },
          { id: "f2", text: "A partner sends 40 suspect IP addresses that no host of yours has ever contacted. Compare them with published C2 server signatures today.", bucket: "jarm", why: "No traffic means nothing passive to compute. JARM probes the server itself." },
          { id: "f3", text: "Group all of the company's Edge browsers as one stack, whatever order each hello arrives in.", bucket: "ja4", why: "It sorts before hashing, so the shuffle doesn't split them." },
          { id: "f4", text: "From sessions already captured, tell whether two suspect servers are configured alike.", bucket: "ja3s", why: "This is the Server Hello side, and it comes from traffic you already hold." },
          { id: "f5", text: "A rule on a modern client has to keep working next month when its extension order has changed again.", bucket: "ja4", why: "An order-sensitive hash would break every connection." },
          { id: "f6", text: "A client hash matched a toolkit's default. Strengthen the match from that same captured session by looking at what answered it.", bucket: "ja3s", why: "The client and server fingerprints as a pair are stronger than either one alone." },
          { id: "f7", text: "A registrar flags a domain created yesterday that might front a team server. Nothing on your network has touched it.", bucket: "jarm", why: "It's active, so you can fingerprint it before anyone connects." },
          { id: "f8", text: "A vendor service from 2019 sends one unchanging hello, and your old SIEM (security information and event management) rule keys on a single MD5.", bucket: "ja3", why: "No shuffle means a stable hash, so the older format still works here." },
        ],
      },
    ],
    // ── Reading 6: does the hello fit the host? ──
    "tls-r6": [
      {
        kind: "sort",
        title: "Does the Hello Fit the Host?",
        prompt: "No hash lookup yet, just a first pass with your eyes: does this hello match the software that should be on this host? Nine sightings from Tessellate's network. A thin hello isn't guilty by itself. What matters is whether it belongs where you found it.",
        primer: {
          fold: true,
          title: "The first pass, before any lookup",
          points: [
            "A current **browser** offers TLS 1.3, a long cipher list, ALPN for HTTP/2, and GREASE (reserved junk values that keep servers tolerant of new features).",
            "A **thin stack** offers few ciphers, stops at TLS 1.2 even if the server could do better, and has no modern extensions.",
            "Thin isn't bad. Embedded devices, older software and simple scripts look like this too. It matters when the host should be running something modern.",
            "**SSLv3, TLS 1.0 and TLS 1.1** in use today are usually a compliance and legacy finding, not an attack in progress. Log them and track them, because such systems tend to be behind in other ways as well.",
          ],
          example: {
            label: "One sighting from another network",
            lines: [
              "A kiosk in a lobby: TLS 1.2, 5 ciphers, no ALPN",
              "It's a kiosk: fits",
              "The same hello from a user's laptop claiming to be a browser: look closer",
            ],
          },
        },
        buckets: [
          { id: "fits", label: "Fits the host" },
          { id: "closer", label: "Mismatch: look closer" },
          { id: "legacy", label: "Legacy finding: track it" },
        ],
        items: [
          { id: "h1", text: "A finance laptop running current Edge: TLS 1.3 offered, 15 ciphers, ALPN h2, GREASE present", bucket: "fits", why: "A rich, current hello from a machine that should produce exactly that." },
          { id: "h2", text: "A card terminal's firmware: TLS 1.2, 4 ciphers, no ALPN", bucket: "fits", why: "Embedded stacks are small. Nothing here contradicts what the device is." },
          { id: "h3", text: "A laptop whose proxy User-Agent says Chrome: TLS 1.2 at most, 6 ciphers, no ALPN", bucket: "closer", why: "Real Chrome doesn't look like this. The claim and the handshake disagree, and that gap is the finding." },
          { id: "h4", text: "A scheduled reporting script on tp-rpt01: a language runtime's default hello, no ALPN", bucket: "fits", why: "Simple automation has a plain hello. Check that the job is known and it stops being interesting." },
          { id: "h5", text: "A 2012 terminal server talking to an internal database over TLS 1.1", bucket: "legacy", why: "End-of-life software still in production. It needs tracking, not an incident." },
          { id: "h6", text: "A managed laptop that has only ever shown browser hellos now also shows 5 ciphers, no ALPN, to one rare destination", bucket: "closer", why: "A new stack on a known host is the point: something else is running there." },
          { id: "h7", text: "A receipt printer's gateway using TLS 1.0 to an internal relay", bucket: "legacy", why: "An old protocol, an old device, and a compliance finding. Log it and raise it with the owner." },
          { id: "h8", text: "An HR manager's MacBook on current Safari: TLS 1.3, ALPN h2, a long cipher list", bucket: "fits", why: "A different hello from Edge's, and still a modern browser." },
          { id: "h9", text: "A domain controller, which should browse nothing, offering a browser-like hello to an outside address", bucket: "closer", why: "The hello is fine and the host is wrong. Fit means fit for that machine, in both directions." },
        ],
      },
    ],
    // ── Warm-up for log analysis 2: first contact ──
    "tls-la2": [
      {
        kind: "queue",
        title: "First Contact: What Explains It?",
        prompt: "Three hosts reached a destination nobody at Tessellate had ever talked to. A first contact is a question, not a verdict. Work out what you'd check, then close what's explained and escalate what isn't.",
        console: "SIEM · First-seen destinations",
        primer: {
          fold: true,
          title: "How to work a first contact",
          points: [
            "Servers do reach new places legitimately. Dependencies, partners and mirrors get added. So verify before you dismiss or overreact.",
            "Look at the **destination**: its JARM against published C2 signatures, threat intelligence, certificate age at first sight.",
            "Look at **your side**: a change record or configuration that names the new destination.",
            "A name that sounds familiar isn't a change record.",
          ],
          example: {
            label: "A first contact from another network",
            lines: [
              "Web server to `feeds.rates-api.example`, public CA, certificate two months old",
              "Change ticket: new exchange-rate feed, destination named, approved last week",
              "Explained. Close it and cite the ticket",
            ],
          },
        },
        actions: [
          { id: "close", label: "Close: explained", tone: "close" },
          { id: "escalate", label: "Escalate: unexplained", tone: "escalate" },
        ],
        alerts: [
          {
            id: "a1", time: "10:22", severity: "Medium", rule: "First-seen TLS destination from server segment", entity: "tp-gw02",
            fields: [{ k: "server_name", v: "api.acquirer-nordic.example" }, { k: "id.resp_p", v: "9443" }, { k: "issuer", v: "Northgate TLS CA 7" }, { k: "Cert age at first sight", v: "40 days" }, { k: "JARM", v: "No match in published C2 lists" }, { k: "Change record", v: "CHG-20417 names this host and port" }],
            context: "The payments gateway. The ticket covers a new acquiring partner going live this week.",
            answer: "close", why: "A public chain, a settled certificate, no JARM match, and a change record that names this exact destination. That's a documented change. Close it and cite the ticket.",
          },
          {
            id: "a2", time: "11:06", severity: "Medium", rule: "First-seen TLS destination from server segment", entity: "tp-jump01",
            fields: [{ k: "server_name", v: "ops-mirror.kestrel-files.example" }, { k: "id.resp_p", v: "443" }, { k: "validation_status", v: "self signed certificate" }, { k: "Cert age at first sight", v: "2 days" }, { k: "JARM", v: "Not yet run" }, { k: "Change record", v: "None found" }],
            context: "The admin jump host. Someone on the platform team said the name 'sounds like one of ours'.",
            answer: "escalate", why: "Sounding familiar isn't a change record. A two-day-old self-signed certificate on a destination no record explains, from a host with admin reach, goes up now, with a JARM scan and a threat-intelligence check running alongside it. Don't rebuild anything yet: the host is your evidence.",
          },
          {
            id: "a3", time: "14:40", severity: "Low", rule: "First-seen TLS destination from server segment", entity: "tp-rpt01",
            fields: [{ k: "server_name", v: "sftp-gw.statementvendor.example" }, { k: "id.resp_p", v: "443" }, { k: "issuer", v: "Northgate TLS CA 7" }, { k: "Cert age at first sight", v: "3 days" }, { k: "JARM", v: "No match in published C2 lists" }, { k: "Change record", v: "CHG-20433: statement vendor migration" }],
            context: "The reporting server. The vendor's new gateway went live on Friday.",
            answer: "close", why: "The certificate is young, because the service is. Age is one signal, and a public chain plus a change record naming this gateway explains it. New doesn't mean bad when you can say why it's new.",
          },
        ],
      },
    ],
    // ── Reading 4: detecting C2 from metadata ──
    "tls-r4": [
      {
        kind: "tune",
        title: "Beacon or Telemetry? Timing and Certificate Age",
        prompt: "Ruaridh wants one rule to surface check-ins, and half of what Tessellate runs also checks in: agents, pollers, wallboards. Each row is one destination over a day. Set the two dials, deploy, and read what your rule really caught. Both dials must trip for the rule to fire.",
        primer: {
          fold: true,
          title: "Reading rhythm and certificate age",
          points: [
            "A **beacon** sleeps, wakes, asks 'anything for me?', and sleeps again. **Jitter** randomises the sleep, but only inside a band, so the gaps still cluster around one number.",
            "**Interval spread** here means the standard deviation of the gaps as a percentage of the mean gap. Human browsing has no timer and runs far above 100%.",
            "A tight spread proves a timer, not an attacker. Security agents, mail clients and licence checks all keep time too.",
            "**Certificate age at first sight** is how old the certificate was the first time this destination appeared on your network. Don't use today's age, because renewals reset it. Don't use the validity period, because the issuer picks that.",
            "TLS 1.3 hides the certificate from your sensor, so for those sessions fetch it yourself with a probe, or look it up in Certificate Transparency logs if a public CA issued it.",
          ],
          example: {
            label: "Working out spread from five gaps on another network",
            lines: [
              "Gaps in seconds: 118, 131, 104, 126, 121. Mean 120, standard deviation about 9",
              "Spread: 9 / 120, about 8%. A timer with jitter",
              "Gaps: 4, 310, 12, 1900, 65. Mean about 460, standard deviation about 730",
              "Spread: far over 100%. A person",
            ],
          },
        },
        eventColumn: "Destination, one day",
        dials: [
          { id: "spread", label: "Interval spread at or below", short: "spread", unit: "%", min: 0, max: 120, step: 1, start: 60, dir: "below" },
          { id: "age", label: "Certificate age at first sight at or below", short: "cert age", unit: "days", min: 0, max: 150, step: 1, start: 30, dir: "below" },
        ],
        events: [
          { id: "c1", label: `${SILENT_NAME} · one laptop, about every 5 minutes`, bad: true, values: { spread: 9, age: 3 } },
          { id: "c2", label: "img.ledgerfont-cdn.example · one laptop, about every 20 minutes", bad: true, values: { spread: 14, age: 11 } },
          { id: "c3", label: "files.northquay-archive.example · one laptop, roughly hourly", bad: true, values: { spread: 23, age: 5 } },
          { id: "c4", label: "api.orchard-metrics.example · one laptop, exactly every 2 minutes", bad: true, values: { spread: 3, age: 1 } },
          { id: "c5", label: "cdn-tiles.vault-sync.example · one server, about every 15 minutes", bad: true, values: { spread: 18, age: 7 } },
          { id: "c6", label: "ledger-archive-sync.example · one laptop, hourly, domain registered last spring", bad: true, values: { spread: 11, age: 140 } },
          { id: "b1", label: "telemetry.sensorvendor.example · EDR heartbeat, every device", bad: false, values: { spread: 2, age: 120 } },
          { id: "b2", label: "mail.tessellatepay.example · mail clients polling, 300 laptops", bad: false, values: { spread: 16, age: 62 } },
          { id: "b3", label: "tms.terminalvendor.example · terminal config check, adopted this spring", bad: false, values: { spread: 4, age: 13 } },
          { id: "b4", label: "payouts-wall.opsdash.example · wallboard auto-refresh, launched this week", bad: false, values: { spread: 25, age: 2 } },
          { id: "b5", label: "docs.tilepartners.example · new partner site, people browsing", bad: false, values: { spread: 110, age: 4 } },
          { id: "b6", label: "licence.finvendor.example · licence check on four servers", bad: false, values: { spread: 6, age: 30 } },
        ],
        goal: { catch: 5, maxFalse: 0 },
        deploys: 4,
        lesson: "Neither dial works alone. Spread lets every agent and poller through, and young certificates include every honest launch. It takes both to split a beacon from telemetry, and the near misses set the numbers: the terminal check sits two days past the oldest beacon, the wallboard just over the loosest one. The hourly check-in on a domain registered last spring gets past you, because attackers can age their infrastructure before using it. So keep rarity, fingerprints and byte sizes in the case. This rule surfaces candidates, it doesn't convict.",
      },
      {
        kind: "worksheet",
        title: "The Shape of a Check-In",
        prompt: "Eight of tp-recon-lt06's sessions to the destination in Ruaridh's capture, from the sensor's connection log. You still can't read a byte. Measure what's left.",
        caption: "Zeek conn.log · 10.72.20.46 to 203.0.113.118:443",
        columns: ["ts", "duration", "orig_bytes", "resp_bytes"],
        rows: [
          ["09:14:02", "0.31", "412", "236"],
          ["09:19:04", "0.29", "412", "236"],
          ["09:23:51", "0.30", "409", "238"],
          ["09:29:02", "0.31", "412", "236"],
          ["09:33:58", "1.84", "415", "52880"],
          ["09:39:03", "2.47", "18340", "236"],
          ["09:44:01", "0.30", "412", "236"],
          ["09:49:02", "0.31", "412", "236"],
        ],
        questions: [
          { id: "mean", q: "What is the average gap between sessions, in seconds?", hint: "Take the first and last times, then divide by the number of gaps, not the number of rows.", answer: ["300", "300 seconds"], why: "2100 seconds over 7 gaps. The gaps run from 287 to 311, clustered tightly around 300. That's jitter inside a band, which no person browsing could produce." },
          { id: "task", q: "One response is far bigger than the rest. At what time did that session start?", hint: "Scan resp_bytes.", answer: ["09:33:58", "9:33:58"], why: "An idle answer is about 236 bytes. A big one means something was waiting: the operator queued a job." },
          { id: "result", q: "What arrived from the laptop at the next check-in, in orig_bytes?", hint: "The row after the big response.", answer: ["18340", "18,340"], why: "A big download, then a big upload one sleep later. That's a job handed out and its result coming back. An idle beacon isn't harmless. It's just waiting, and this one wasn't." },
          { id: "indep", q: "A backup agent wakes on a strict five-minute timer and sends whatever changed. Would its orig_bytes stay this flat? (yes/no)", hint: "What decides how much it sends?", answer: ["no", "n"], why: "Same clock, very different sizes. Timing and size are separate measurements, so a host showing both a tight rhythm and flat byte counts gives you two independent signals, both from metadata alone." },
        ],
      },
      {
        kind: "intercept",
        title: "Escalate or Baseline: One Signal or Several?",
        prompt: "The queue before Friday's run. Each line is what the sensor flagged and what the context adds. Every one has at least one scary word in it. Escalate only what holds up in combination.",
        protect: "the settlement run",
        blockLabel: "Escalate",
        passLabel: "Baseline",
        seconds: 12,
        items: [
          { id: "i1", text: "SNI login.bankportal-secure.example", sub: "Address in a budget VPS range, first seen today, one host", bad: true, why: "A bank's name on rented hosting with no relation to it needs no decryption to see. SNI against IP ownership is a strong check, and here rarity backs it up." },
          { id: "i2", text: "Self-signed certificate, 4 days old at first sight", sub: "One laptop, every 10 minutes, same 380 bytes each time", bad: true, why: "Recent, rare, on a rhythm, and flat in size. Several independent signals agree." },
          { id: "i3", text: "JA4 matches a C2 framework's documented default", sub: "One server, destination new this week", bad: true, why: "A match on an unmodified default is strong evidence, and the destination fits. Remember the reverse doesn't hold: no match clears nothing." },
          { id: "i4", text: "Public CA certificate, 2 days old", sub: "invoice-cdn-static.example, one host, tight 15-minute rhythm, byte counts within 6 bytes", bad: true, why: "A public chain only proves someone controls the domain, and attackers get free certificates too. The rhythm, sizes and rarity make the case." },
          { id: "i5", text: "Thin hello, no ALPN, claims to be Chrome", sub: "One managed laptop, first contact with a rare address", bad: true, why: "A claim the handshake contradicts, on a host that should be modern, heading somewhere nobody else goes." },
          { id: "i6", text: "Self-signed certificate on 10.72.9.12", sub: "Printer fleet console, 2 years old, 60 clients", bad: false, why: "Old, internal, popular and owned. Self-signed by itself tells you almost nothing." },
          { id: "i7", text: "Public CA certificate, 5 days old", sub: "Scheduled renewal, destination 3 years in traffic, 300 hosts", bad: false, why: "A new certificate on an old relationship. Rotation resets today's age, not first sight." },
          { id: "i8", text: "Tight heartbeat, every 2 minutes", sub: "EDR vendor, every laptop, 3-year history", bad: false, why: "Tight timing proves a timer. Widespread, long-lived and named: that's telemetry." },
          { id: "i9", text: "JA3 not on the browser reference list", sub: "Daily 06:00 reporting script, known owner, same internal host for a year", bad: false, why: "An unlisted fingerprint means a library the list doesn't cover. Scripts are usually exactly that." },
          { id: "i10", text: "40 sessions to a brand-new site", sub: "One host, human-paced gaps, sizes all over the place, a vendor's webinar page", bad: false, why: "Rare, but there's no rhythm and no consistency. Someone was watching a webinar." },
        ],
        lesson: "Any one signal has an innocent explanation, and the context line is where you find it. A case worth escalating is several independent signals pointing the same way: rare, recently certified, thin or odd in its fingerprint, on a rhythm, flat in size, with a name that doesn't fit its hosting. All of it is visible without decrypting anything.",
      },
    ],
    // ── Warm-up for log analysis 1: from network to process ──
    "tls-la1": [
      {
        kind: "sequence",
        title: "From Envelope to Process: The Order of Work",
        prompt: "The network has told you which host and when. It can't tell you which program. Last spring Ruaridh worked a beacon-shaped host in the Legal team, and this was the order that held up. Rebuild it.",
        items: [
          { id: "contain", text: "Contain the host and block the destination together", note: "Only once you know what you're removing and where else it lives." },
          { id: "shape", text: "Confirm the shape across all the sessions: same destination, rhythm and sizes", note: "One session proves nothing. The pattern is the evidence." },
          { id: "fp", text: "Check the client and server fingerprints against known toolkits", note: "A match adds weight. No match proves nothing." },
          { id: "proc", text: "Use EDR on the host to find the process that owns those connections", note: "EDR (endpoint detection and response) records which program opened each connection. The network never can." },
          { id: "scope", text: "Pivot on the fingerprint and destination to find other hosts", note: "If this host has it, ask who else does." },
          { id: "record", text: "Write up the case and keep the destination as an indicator", note: "The next analyst starts from your notes." },
        ],
        order: ["shape", "proc", "fp", "scope", "contain", "record"],
        doneNote: "A sensor on the wire sees addresses and ports, and the program that opened the socket exists only on the host.",
      },
    ],
    // ── Warm-up for the query: thresholds that still catch it ──
    "tls-qf1": [
      {
        kind: "worksheet",
        title: "Thresholds That Would Still Catch It",
        prompt: "Last quarter Ruaridh ran a beacon hunt over port 9443, where Tessellate's partner APIs live, and wants a second opinion on the thresholds. The query ends in `| where SessionCount > 200 | where StdevBytesOut < 40`. Here's what the summarize step returned, before those two lines.",
        caption: "summarize SessionCount, StdevBytesOut by SourceIp, DestinationIp, JA3Hash",
        primer: {
          fold: true,
          title: "Choosing a floor and a ceiling",
          points: [
            "`SessionCount` is a **floor**: it has to sit **below** the count of the host you want. Set it at or above that count, and the host drops out.",
            "`StdevBytesOut` is a **ceiling**: it has to sit **above** that host's spread. `stdev()` gives low numbers for flat traffic.",
            "There's no single right number. Any value that still catches the pattern and leaves the noise behind will do.",
            "`by SourceIp, DestinationIp, JA3Hash` gives each destination its own row, with the hash in it to pivot on afterwards. To follow one source across rotating destinations in a single row, use `by SourceIp, JA3Hash` with `dcount(DestinationIp)`.",
          ],
          example: {
            label: "One host from another network: 500 sessions, byte spread 50",
            lines: [
              "`SessionCount > 400`: keeps it. `SessionCount > 500`: loses it, because 500 is not above 500",
              "`StdevBytesOut < 60`: keeps it. `StdevBytesOut < 50`: loses it",
            ],
          },
        },
        columns: ["SourceIp", "DestinationIp", "JA3Hash (first 8)", "SessionCount", "StdevBytesOut"],
        rows: [
          ["10.72.31.4", "203.0.113.131", "a93c10d7", "288", "31"],
          ["10.72.31.4", "198.51.100.61", "5d20c7e1", "64", "2210"],
          ["10.72.5.60", "198.51.100.62", "a93c10d7", "22", "11"],
          ["10.72.31.9", "203.0.113.140", "a93c10d7", "190", "28"],
          ["10.72.20.77", "198.51.100.64", "c2e7f410", "310", "1840"],
          ["10.72.20.58", "198.51.100.90", "d04a8e1b", "1440", "3"],
        ],
        questions: [
          { id: "left", q: "How many rows survive both filters?", hint: "A row must clear the floor and sit under the ceiling.", answer: ["2", "two"], why: "288 with 31, and 1440 with 3. The busy browser fails the ceiling. The last row is telemetry, which is why these candidates still need a look." },
          { id: "miss", q: "Row 4 has the same JA3 as row 1 but misses the rule. What is the highest whole-number floor that still keeps it?", hint: "The rule uses a strict greater-than.", answer: ["189"], why: "190 is above 189 and not above 190. A slower host on the same library shouldn't fall through a floor you set for a faster one." },
          { id: "raise", q: "Someone raises the floor to 300 to cut noise. Does the rule still catch 10.72.31.4 in row 1? (yes/no)", hint: "Compare 300 with row 1's SessionCount.", answer: ["no", "n"], why: "288 is under the new floor, so the host you built the rule for has gone. Test every threshold against a known example before you ship it." },
          { id: "group", q: "Rows 1 and 4 reach different destinations. Which column ties them together?", hint: "What's the same in both rows?", answer: ["JA3Hash", "JA3", "ja3 hash"], why: "The shared hash is your pivot once the rows are in front of you. This query still gives each destination its own row. To see a source rotating through destinations in one row, group by SourceIp and JA3Hash and add dcount(DestinationIp)." },
        ],
      },
    ],
    // ── Reading 5: interception and its limits ──
    "tls-r5": [
      {
        kind: "simulate",
        title: "What the Proxy Can Open",
        prompt: "The obvious question from Tessellate's CFO: why not just decrypt it? tp-prox01 opens most of the building's HTTPS, and never the settlement floor's. Run each connection through it and see what the inspection actually gets.",
        primer: {
          fold: true,
          title: "How TLS interception works",
          points: [
            "A forward proxy is a planned man-in-the-middle: it ends the client's TLS session with a certificate it makes on the spot, opens its own session to the real server, and inspects the content between the two.",
            "It works only because an **internal CA** has been pushed into every managed device's trust store. Without that, every site shows a warning.",
            "**Certificate pinning** means an application carries the certificate or key it expects inside its own code. Anything else is rejected, whatever the trust store says.",
            "Some traffic is left out by policy: banking, healthcare, sometimes personal webmail, because of legal and privacy risk.",
            "**HSTS** (HTTP Strict Transport Security) only removes the click-through on an untrusted certificate. A proxy certificate from a trusted internal CA still passes.",
          ],
          example: {
            label: "One connection from another network",
            lines: [
              "Managed laptop, browser, shopping site: the device trusts the CA, the category is allowed, the browser accepts the substitute",
              "Result: decrypted and inspected",
            ],
          },
        },
        checks: [
          { name: "Trusts internal CA", question: "Does this device trust the proxy's CA?" },
          { name: "Not excluded", question: "Does policy allow this category to be decrypted?" },
          { name: "Accepts a substitute", question: "Will the application accept the proxy's certificate?" },
        ],
        scenarios: [
          {
            id: "open", label: "Managed laptop, Edge, a news site", detail: "The everyday case",
            results: ["pass", "pass", "pass"],
            why: ["The CA was pushed by device management.", "News is allowed.", "The browser validates the proxy's certificate like any other."],
            verdict: "Decrypted. Content inspection works, and the user sees a normal padlock.",
          },
          {
            id: "hsts", label: "Managed laptop, Edge, a site on the HSTS preload list", detail: "The browser will never let the user click through a warning here",
            results: ["pass", "pass", "pass"],
            why: ["The CA is trusted.", "The category is allowed.", "HSTS removes the click-through, but there's nothing to click through: the proxy's chain is trusted."],
            verdict: "Still decrypted. HSTS is often blamed for breaking inspection. Pinning or a missing internal CA is what really stops it.",
          },
          {
            id: "bank", label: "Managed laptop, Edge, a personal bank", detail: "Category: Financial",
            results: ["pass", "fail", "pass"],
            why: ["The CA is trusted.", "Policy excludes it, so that the company doesn't take on liability for seeing it.", "It would have worked."],
            verdict: "Passed through unopened. Metadata only, by choice. The settlement floor is excluded for the same kind of reason, and that's the Sealed Room.",
          },
          {
            id: "byod", label: "A contractor's own laptop", detail: "Never enrolled in device management",
            results: ["fail", "pass", "fail"],
            why: ["No internal CA in its trust store, and there won't be one.", "The category is allowed.", "A browser refuses a certificate it can't chain to a trusted root, so every site would show a warning."],
            verdict: "It can't be intercepted without certificate warnings, so it's bypassed. For BYOD (bring your own device), IoT and third-party kit, metadata isn't the fallback. It's the only option.",
          },
          {
            id: "pin", label: "Managed laptop, a desktop messaging client", detail: "The client ships with its server's key built in",
            results: ["pass", "pass", "fail"],
            why: ["The CA is trusted by the operating system.", "The category is allowed.", "The app compares what it gets with the key it carries, and the proxy's isn't it."],
            verdict: "The client rejects the proxy's certificate and the handshake ends in a certificate alert. Pinning is a security feature, and several C2 frameworks use it for the same reason. Add it to the bypass list or leave it failing, but you get the envelope and never the letter.",
          },
        ],
      },
      {
        kind: "worksheet",
        title: "One App Fails at the Proxy",
        prompt: "Treasury raised a ticket: 'the internet is broken'. Here's today's summary from tp-prox01. Before anyone restarts anything, read what the failure pattern says.",
        caption: "tp-prox01 · TLS inspection summary · today",
        columns: ["Client", "Process", "SNI", "Proxy result", "Client TLS alert", "Sessions"],
        rows: [
          ["tp-fin-lt11", "msedge.exe", "news.finwire.example", "decrypted", "-", "212"],
          ["tp-hr-lt03", "msedge.exe", "board.merchantdesk.example", "decrypted", "-", "118"],
          ["tp-tsy-lt02", "tokenvault.exe", "api.tokenvault.example", "handshake failed", "certificate_unknown (46)", "41"],
          ["tp-tsy-lt05", "tokenvault.exe", "api.tokenvault.example", "handshake failed", "certificate_unknown (46)", "37"],
          ["tp-tsy-lt02", "msedge.exe", "docs.tilepartners.example", "decrypted", "-", "64"],
          ["tp-fin-lt11", "msedge.exe", "mybank-retail.example", "bypassed: Financial", "-", "9"],
          ["tp-vis-07", "chrome.exe", "docs.tilepartners.example", "bypassed: unmanaged device", "-", "22"],
        ],
        questions: [
          { id: "apps", q: "How many different processes failed the handshake?", hint: "Read the Proxy result column, then the Process column.", answer: ["1", "one"], why: "Only one, on two laptops. The same laptop's browser is fine, so the laptop, the network and the proxy all work." },
          { id: "ca", q: "If the proxy's CA had expired, would the msedge.exe rows still say decrypted? (yes/no)", hint: "What would an expired CA do to every client that trusts it?", answer: ["no", "n"], why: "A dead CA breaks everyone at once. One failing application, with everything else healthy, points at that application." },
          { id: "dark", q: "In how many rows does inspection see no content?", hint: "Count the rows that don't say decrypted.", answer: ["4", "four"], why: "Two failed and two bypassed. Mature interception still leaves gaps you need metadata skills for, and those gaps are where an attacker would prefer to be." },
        ],
      },
    ],
    // ── The boss: age, rarity, recurrence, owner ──
    "tls-ac1": [
      {
        kind: "queue",
        title: "Certificate Flags, Three Verdicts",
        prompt: "Four alerts, all on internal segments, all with a certificate flag. Ruaridh's last lesson before the run: read the values behind the flags, ask the owner, then rule on each one.",
        console: "SIEM · Internal TLS anomalies",
        primer: {
          fold: true,
          title: "Three verdicts, and what separates them",
          points: [
            "**True positive:** the rule saw something real, and it's malicious or unauthorised.",
            "**Benign true positive:** the rule's claim is correct, and the activity is approved. Close it and record what approved it.",
            "**False positive:** the rule misfired, because what it claims isn't true. Fix the rule or the data behind it.",
            "A flag is a question. Answer it with values: certificate **age**, how many hosts already use the destination (**rarity**), whether it **recurs** on a known schedule, and what the **owner** confirms.",
            "A familiar name clears nothing if the values changed. Compare today with its own history.",
          ],
          example: {
            label: "An alert from another network",
            lines: [
              "A rule fires on a mail link to a domain registered four days ago",
              "It's the awareness team's booked phishing exercise, sign-off on file. The rule is right about the domain, and the activity is approved: benign true positive",
            ],
          },
        },
        actions: [
          { id: "tp", label: "True positive: escalate", tone: "escalate" },
          { id: "btp", label: "Benign true positive: close with evidence", tone: "close" },
          { id: "fp", label: "False positive: fix the rule", tone: "close" },
        ],
        alerts: [
          {
            id: "k1", time: "Tue 02:15", severity: "Low", rule: "Expired certificate in internal session", entity: "tp-vscan01",
            fields: [{ k: "validation_status", v: "certificate has expired" }, { k: "id.resp_h", v: "10.72.14.23" }, { k: "Hosts touched in 40 minutes", v: "1,900" }, { k: "Scan calendar", v: "Monthly sweep, window booked for 02:00 to 03:00" }, { k: "Vulnerability team says", v: "That's our scanner, in its window. The lapsed certificate is on our findings list." }],
            context: "The sanctioned vulnerability scanner opens a session to every listening port it can find, so it reached a test service whose certificate lapsed in the summer.",
            answer: "btp", why: "The rule told the truth: that certificate has lapsed, and a session did touch it. The session came from a tool the company runs on purpose, inside its booked slot. Nothing here was misread, so don't mark the rule wrong. Record the scanner and the booking, and send the lapsed certificate to the service's owner.",
          },
          {
            id: "k2", time: "Tue 23:18", severity: "Medium", rule: "Internal certificate anomaly", entity: "tp-batch03",
            fields: [{ k: "id.resp_p", v: "9443" }, { k: "validation_status", v: "self signed certificate" }, { k: "Cert age", v: "2 days" }, { k: "Hosts seen before today", v: "0" }, { k: "Recurrence", v: "None" }, { k: "IT says", v: "10.72.9.77 isn't in the inventory. Owner unknown." }],
            context: "A batch server, late at night.",
            answer: "tp", why: "Internal doesn't mean safe. A two-day-old certificate on an address nobody owns, first contact, no schedule. An attacker who has reached the inside sets up their own listeners too.",
          },
          {
            id: "k3", time: "Wed 09:02", severity: "Low", rule: "Untrusted certificate chain on internal segment", entity: "tp-wiki01",
            fields: [{ k: "validation_status", v: "unable to get local issuer certificate" }, { k: "issuer", v: "CN=Tessellate Internal CA 2" }, { k: "Cert age", v: "120 days" }, { k: "Hosts seen before today", v: "300" }, { k: "IT says", v: "That's our own CA. The sensor was rebuilt on Friday, and its trust store has no internal root." }],
            context: "Three hundred more of these arrived this morning. All of them are for internal sites.",
            answer: "fp", why: "The chain is fine. The sensor is what's broken, because it lost the internal root, so the rule's claim isn't true of this traffic. Restore the root in the sensor. Nothing on the wiki needs changing.",
          },
          {
            id: "k4", time: "Wed 23:40", severity: "Medium", rule: "Internal certificate anomaly", entity: "tp-kld02",
            fields: [{ k: "id.resp_p", v: "9443" }, { k: "validation_status", v: "self signed certificate" }, { k: "Cert age", v: "1 day (was 402 days last Sunday)" }, { k: "Hosts seen before today", v: "58" }, { k: "Recurrence", v: "Sundays 04:10. This is a Wednesday night" }, { k: "IT says", v: "No change on record. We didn't touch it." }],
            context: "The key loader for the card terminals, an appliance everyone knows.",
            answer: "tp", why: "A familiar host with its history broken: the certificate was replaced overnight with no ticket, and a session arrived off schedule. Rarity looks fine, and the other values don't. Compare a known host with itself, not just with the fleet.",
          },
        ],
      },
    ],
  },
};
