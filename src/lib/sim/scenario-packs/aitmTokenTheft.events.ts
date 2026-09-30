/**
 * Events-only half of the ./aitmTokenTheft.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./aitmTokenTheft.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

/** Telemetry half of `buildAitmTokenTheftScenario`: the events and the story title, no answer key. */
export function aitmTokenTheftScenarioEvents() {
  const B = new Date("2026-03-17T07:12:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // ── Cast ───────────────────────────────────────────────────────────────────
  const victim = "m.delgado@nexacorp.com";          // Financial Controller, standard user
  const traveller = "a.rosen@nexacorp.com";         // benign look-alike: real trip, real VPN

  // ── Infrastructure ─────────────────────────────────────────────────────────
  const corpEgress = "81.174.22.63";                // Zscaler / corporate egress, London
  const proxyIp = "45.87.81.126";                   // reverse-proxy front end, Amsterdam (AS60068)
  const replayIp = "91.132.139.204";                // attacker workstation, Frankfurt (AS51167)
  const vpnEgress = "194.145.227.18";               // corporate VPN concentrator, Frankfurt (AS202422)
  const phishHost = "login.nexacorp-sso.com";
  const phishUrl = `https://${phishHost}/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca`;

  // One browser session, issued once, used twice. This is the whole scenario.
  const sessionId = "0f2c1e64-3b7a-4c19-9d84-5a6e2f8b17d3";

  // EDR↔scenario integration (Phase 4): this is a control-plane-only incident —
  // AiTM reverse-proxy phishing and a replayed session cookie against Entra/M365,
  // with no host EDR events and no process to walk. edr_scope "non_edr": there is
  // nothing to investigate in the EDR console. No is_detection (no EDR detections);
  // edr_scope goes on the identity detection that opens the ticket — the
  // non-interactive cookie-replay sign-in.
  const INCIDENT = "inc:aitm:1";

  const events: TelemetryEvent[] = [
    // ── 1. The lure ──────────────────────────────────────────────────────────
    {
      id: "aitm_01_lure",
      ts: T(0),
      source: "email_gateway", vendor: "Proofpoint",
      event_type: "email_received", severity: "medium", mitre_technique: "T1566.002",
      user_email: victim, user_title: "Financial Controller",
      network: { url: phishUrl, domain: phishHost },
      description:
        "A signature-request mail was delivered to m.delgado from billing@docu-sign-secure.com, display name 'NexaCorp IT Service Desk', with a link to login.nexacorp-sso.com.",
      raw: {
        "pps.QID": "4A2F91C037",
        "pps.messageID": "<f21c9a4e-7b03-4d16-8e5a-2c9047ab6631@docu-sign-secure.com>",
        "pps.sender": "billing@docu-sign-secure.com",
        "pps.headerFrom": "\"NexaCorp IT Service Desk\" <no-reply@docu-sign-secure.com>",
        "pps.recipient": victim,
        "pps.subject": "Action required: Q1 vendor agreement awaiting your signature",
        "pps.senderIP": "185.53.178.9",
        "pps.spf": "pass",
        "pps.dkim": "pass",
        "pps.dmarc": "none",
        "pps.phishScore": 41,
        "pps.spamScore": 12,
        "pps.policyRoutes": ["default_inbound", "executive_finance"],
        "pps.messageParts[0].filename": "text/html",
        "pps.urls[0]": phishUrl,
        "pps.urls[0].rewritten": "https://urldefense.proofpoint.com/v2/url?u=https-3A__login.nexacorp-2Dsso.com",
        "pps.action": "delivered",
      },
    },

    // ── 2. The click ─────────────────────────────────────────────────────────
    {
      id: "aitm_02_click",
      ts: T(4 * MIN),
      source: "email_gateway", vendor: "Proofpoint",
      event_type: "email_clicked", severity: "medium", mitre_technique: "T1566.002",
      user_email: victim, user_title: "Financial Controller",
      src_ip: corpEgress,
      geo: { country: "United Kingdom", city: "London", latitude: 51.5074, longitude: -0.1278 },
      network: { url: phishUrl, domain: phishHost, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92" },
      description:
        "URL Defense recorded m.delgado following the rewritten link four minutes after delivery, from the London corporate egress on Edge. Click status: permitted.",
      raw: {
        "pps.clickTime": T(4 * MIN),
        "pps.QID": "4A2F91C037",
        "pps.messageID": "<f21c9a4e-7b03-4d16-8e5a-2c9047ab6631@docu-sign-secure.com>",
        "pps.recipient": victim,
        "pps.url": phishUrl,
        "pps.clickIP": corpEgress,
        "pps.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
        "pps.clickStatus": "permitted",
        "pps.sender": "billing@docu-sign-secure.com",
      },
    },

    // ── 3. Name resolution for the look-alike ────────────────────────────────
    {
      id: "aitm_03_dns",
      ts: T(4 * MIN + 6 * SEC),
      source: "dns", vendor: "Infoblox DNS",
      event_type: "dns_query", severity: "low",
      hostname: "LT-FIN-0442", user_email: victim,
      src_ip: "10.42.18.77",
      dns: { query: phishHost, query_type: "A", response: proxyIp, rcode: "NOERROR" },
      description:
        "LT-FIN-0442 resolved login.nexacorp-sso.com to a single A record, 45.87.81.126, answered NOERROR from the internal Infoblox view.",
      raw: {
        "infoblox.client_ip": "10.42.18.77",
        "infoblox.query_name": phishHost,
        "infoblox.query_type": "A",
        "infoblox.rcode": "NOERROR",
        "infoblox.answer": proxyIp,
        "infoblox.ttl": 300,
        "infoblox.view": "internal",
        "infoblox.member": "ns-lon-01.nexacorp.com",
        "infoblox.transport": "UDP",
      },
    },

    // ── 4. Browser reaches the reverse proxy ─────────────────────────────────
    {
      id: "aitm_04_proxy_get",
      ts: T(4 * MIN + 9 * SEC),
      source: "proxy", vendor: "Zscaler Internet Access",
      event_type: "http_request", severity: "medium", mitre_technique: "T1557",
      hostname: "LT-FIN-0442", user_email: victim,
      src_ip: corpEgress, dst_ip: proxyIp, dst_port: 443, protocol: "tcp",
      geo: { country: "United Kingdom", city: "London" },
      network: { url: phishUrl, domain: phishHost, method: "GET", status: 200, bytes_in: 48213, bytes_out: 1024 },
      description:
        "m.delgado's browser loaded a sign-in page from login.nexacorp-sso.com, 200 returned. Zscaler categorised the host as Newly Registered Domains and allowed it.",
      raw: {
        "zscaler.login": victim,
        "zscaler.department": "Finance",
        "zscaler.location": "London HQ",
        "zscaler.cip": "10.42.18.77",
        "zscaler.sip": proxyIp,
        "zscaler.hostname": phishHost,
        "zscaler.url": phishUrl,
        "zscaler.urlcategory": "Newly Registered Domains",
        "zscaler.urlclass": "Business Use",
        "zscaler.reqmethod": "GET",
        "zscaler.respcode": 200,
        "zscaler.reqsize": 1024,
        "zscaler.respsize": 48213,
        "zscaler.useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
        "zscaler.action": "Allowed",
        "zscaler.threatname": "None",
        "zscaler.appname": "General Browsing",
        "zscaler.serverip": proxyIp,
        "zscaler.clienttranstime": 214,
      },
    },

    // ── 5. Credentials + live MFA response posted to the proxy ───────────────
    {
      id: "aitm_05_proxy_post",
      ts: T(5 * MIN + 41 * SEC),
      source: "proxy", vendor: "Zscaler Internet Access",
      event_type: "http_request", severity: "high", mitre_technique: "T1557",
      hostname: "LT-FIN-0442", user_email: victim,
      src_ip: corpEgress, dst_ip: proxyIp, dst_port: 443, protocol: "tcp",
      geo: { country: "United Kingdom", city: "London" },
      network: { url: `https://${phishHost}/common/login`, domain: phishHost, method: "POST", status: 302, bytes_in: 2211, bytes_out: 3874 },
      description:
        "A POST to /common/login on login.nexacorp-sso.com carried 3,874 bytes of form data and the host answered 302. Zscaler allowed the request.",
      raw: {
        "zscaler.login": victim,
        "zscaler.department": "Finance",
        "zscaler.location": "London HQ",
        "zscaler.cip": "10.42.18.77",
        "zscaler.sip": proxyIp,
        "zscaler.hostname": phishHost,
        "zscaler.url": `https://${phishHost}/common/login`,
        "zscaler.urlcategory": "Newly Registered Domains",
        "zscaler.reqmethod": "POST",
        "zscaler.respcode": 302,
        "zscaler.reqsize": 3874,
        "zscaler.respsize": 2211,
        "zscaler.useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
        "zscaler.action": "Allowed",
        "zscaler.threatname": "None",
        "zscaler.serverip": proxyIp,
        "zscaler.clienttranstime": 1873,
      },
    },

    // ── 6. The real sign-in — MFA genuinely satisfied ────────────────────────
    {
      id: "aitm_06_entra_signin",
      ts: T(6 * MIN + 3 * SEC),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "auth_success", severity: "high", mitre_technique: "T1557",
      user_email: victim, user_title: "Financial Controller",
      src_ip: proxyIp,
      geo: { country: "Netherlands", city: "Amsterdam", latitude: 52.3676, longitude: 4.9041 },
      authentication: { method: "Password + Microsoft Authenticator", mfa_type: "push", result: "success" },
      description:
        "Entra ID recorded a successful interactive sign-in for m.delgado, multifactor satisfied by a live Authenticator approval, from 45.87.81.126 in Amsterdam (AS60068).",
      fp_explanation:
        "Every quality signal on this record is green — MFA satisfied, Conditional Access success, sign-in risk none. Analysts who triage on outcome fields alone will close it.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "9c1e0b47-52aa-4f6d-b3c1-77e0d2a5c418",
        "azure.signinlogs.properties.createdDateTime": T(6 * MIN + 3 * SEC),
        "azure.signinlogs.properties.userPrincipalName": victim,
        "azure.signinlogs.properties.userDisplayName": "Maria Delgado",
        "azure.signinlogs.properties.userId": "b8f42a09-6d31-4c7e-9a15-3e0c8b71d4f2",
        "azure.signinlogs.properties.correlationId": "2d7f5a10-9c48-4b62-8e03-6a1d9f47c205",
        "azure.signinlogs.properties.sessionId": sessionId,
        "azure.signinlogs.properties.appDisplayName": "Microsoft Office",
        "azure.signinlogs.properties.appId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "azure.signinlogs.properties.resourceDisplayName": "Microsoft Graph",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.isInteractive": true,
        "azure.signinlogs.properties.ipAddress": proxyIp,
        "azure.signinlogs.properties.autonomousSystemNumber": 60068,
        "azure.signinlogs.properties.location.city": "Amsterdam",
        "azure.signinlogs.properties.location.state": "North Holland",
        "azure.signinlogs.properties.location.countryOrRegion": "NL",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 52.3676,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": 4.9041,
        "azure.signinlogs.properties.deviceDetail.deviceId": "",
        "azure.signinlogs.properties.deviceDetail.displayName": "",
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 11",
        "azure.signinlogs.properties.deviceDetail.browser": "Edge 122.0.2365",
        "azure.signinlogs.properties.deviceDetail.isCompliant": false,
        "azure.signinlogs.properties.deviceDetail.isManaged": false,
        "azure.signinlogs.properties.deviceDetail.trustType": "",
        "azure.signinlogs.properties.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.authenticationDetails": [
          {
            authenticationStepDateTime: T(5 * MIN + 44 * SEC),
            authenticationMethod: "Password",
            authenticationMethodDetail: "Password in the cloud",
            succeeded: true,
            authenticationStepResultDetail: "Correct password",
            authenticationStepRequirement: "Primary authentication",
          },
          {
            authenticationStepDateTime: T(6 * MIN + 1 * SEC),
            authenticationMethod: "Mobile app notification",
            authenticationMethodDetail: "Microsoft Authenticator",
            succeeded: true,
            authenticationStepResultDetail: "MFA completed in Azure AD",
            authenticationStepRequirement: "Multifactor authentication",
          },
        ],
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.appliedConditionalAccessPolicies": [
          {
            id: "1f0b6c93-7d24-4a5e-8b90-c3f27a641e58",
            displayName: "Require MFA for all users",
            result: "success",
            enforcedGrantControls: ["Mfa"],
            enforcedSessionControls: [],
          },
        ],
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.riskState": "none",
        "azure.signinlogs.properties.riskEventTypes_v2": [],
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "none",
        "azure.signinlogs.properties.status.errorCode": 0,
        "azure.signinlogs.resultType": "0",
      },
    },

    // ── 7. Proxy hands the victim on to the real site ────────────────────────
    {
      id: "aitm_07_redirect",
      ts: T(6 * MIN + 12 * SEC),
      source: "proxy", vendor: "Zscaler Internet Access",
      event_type: "http_request", severity: "informational",
      hostname: "LT-FIN-0442", user_email: victim,
      src_ip: corpEgress, dst_ip: "13.107.6.156", dst_port: 443, protocol: "tcp",
      network: { url: "https://www.office.com/", domain: "www.office.com", method: "GET", status: 200, bytes_in: 92440, bytes_out: 1470 },
      description:
        "Nine seconds after the sign-in completed the browser loaded www.office.com, with https://login.nexacorp-sso.com/common/login recorded as the referer.",
      raw: {
        "zscaler.login": victim,
        "zscaler.location": "London HQ",
        "zscaler.cip": "10.42.18.77",
        "zscaler.sip": "13.107.6.156",
        "zscaler.hostname": "www.office.com",
        "zscaler.url": "https://www.office.com/",
        "zscaler.urlcategory": "Professional Services",
        "zscaler.reqmethod": "GET",
        "zscaler.respcode": 200,
        "zscaler.referer": `https://${phishHost}/common/login`,
        "zscaler.reqsize": 1470,
        "zscaler.respsize": 92440,
        "zscaler.action": "Allowed",
        "zscaler.appname": "Microsoft Office 365",
        "zscaler.threatname": "None",
      },
    },

    // ── 8. BENIGN look-alike: a real trip on the corporate VPN ───────────────
    {
      id: "aitm_08_benign_travel",
      ts: T(9 * MIN),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "auth_success", severity: "low",
      user_email: traveller, user_title: "Regional Sales Lead",
      src_ip: vpnEgress,
      geo: { country: "Germany", city: "Frankfurt", latitude: 50.1109, longitude: 8.6821 },
      authentication: { method: "Password + Microsoft Authenticator", mfa_type: "push", result: "success" },
      description:
        "a.rosen signed in successfully from Frankfurt (AS202422) on the Entra-joined device LT-SLS-0117, with an Authenticator approval and a named corporate VPN network location.",
      fp_explanation:
        "Benign. This is what ordinary travel looks like: a new interactive sign-in with its own session and its own second factor, from a trusted named location on a managed device. Compare it field-for-field with aitm_09 before escalating either one.",
      it_verify_result: "confirmed",
      it_verify_message: "HR travel calendar shows a.rosen at the Frankfurt partner summit 16–19 March; device LT-SLS-0117 is Entra-joined and Intune-compliant.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "5b8d3f21-0c47-4e9a-91d6-28f0a4b7c635",
        "azure.signinlogs.properties.createdDateTime": T(9 * MIN),
        "azure.signinlogs.properties.userPrincipalName": traveller,
        "azure.signinlogs.properties.userDisplayName": "Anat Rosen",
        "azure.signinlogs.properties.userId": "e40a72c8-1b95-4d3f-86ac-90f7d5e2418b",
        "azure.signinlogs.properties.correlationId": "7a3c9e56-4f20-48b1-95d7-0e6b23fa8c74",
        "azure.signinlogs.properties.sessionId": "c94b7d20-8e13-4af6-b052-1d7c6e309a48",
        "azure.signinlogs.properties.appDisplayName": "Microsoft Office",
        "azure.signinlogs.properties.appId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "azure.signinlogs.properties.resourceDisplayName": "Microsoft Graph",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.isInteractive": true,
        "azure.signinlogs.properties.ipAddress": vpnEgress,
        "azure.signinlogs.properties.autonomousSystemNumber": 202422,
        "azure.signinlogs.properties.location.city": "Frankfurt am Main",
        "azure.signinlogs.properties.location.state": "Hesse",
        "azure.signinlogs.properties.location.countryOrRegion": "DE",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 50.1109,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": 8.6821,
        "azure.signinlogs.properties.deviceDetail.deviceId": "a1c6f803-95b2-4e77-8d14-6f2093ac5b71",
        "azure.signinlogs.properties.deviceDetail.displayName": "LT-SLS-0117",
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 11",
        "azure.signinlogs.properties.deviceDetail.browser": "Edge 122.0.2365",
        "azure.signinlogs.properties.deviceDetail.isCompliant": true,
        "azure.signinlogs.properties.deviceDetail.isManaged": true,
        "azure.signinlogs.properties.deviceDetail.trustType": "Azure AD joined",
        "azure.signinlogs.properties.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.authenticationDetails": [
          {
            authenticationStepDateTime: T(8 * MIN + 51 * SEC),
            authenticationMethod: "Password",
            authenticationMethodDetail: "Password in the cloud",
            succeeded: true,
            authenticationStepResultDetail: "Correct password",
            authenticationStepRequirement: "Primary authentication",
          },
          {
            authenticationStepDateTime: T(8 * MIN + 58 * SEC),
            authenticationMethod: "Mobile app notification",
            authenticationMethodDetail: "Microsoft Authenticator",
            succeeded: true,
            authenticationStepResultDetail: "MFA completed in Azure AD",
            authenticationStepRequirement: "Multifactor authentication",
          },
        ],
        "azure.signinlogs.properties.networkLocationDetails": [
          { networkType: "namedNetwork", networkNames: ["Corporate VPN — Frankfurt POP"] },
        ],
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.riskState": "none",
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "none",
        "azure.signinlogs.properties.status.errorCode": 0,
        "azure.signinlogs.resultType": "0",
      },
    },

    // ── 9. THE CRUX — same session, different everything else ────────────────
    {
      id: "aitm_09_cookie_replay",
      ts: T(12 * MIN + 3 * SEC),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "auth_success", severity: "critical", mitre_technique: "T1550.004",
      user_email: victim, user_title: "Financial Controller",
      src_ip: replayIp,
      geo: { country: "Germany", city: "Frankfurt", latitude: 50.1109, longitude: 8.6821 },
      edr_scope: "non_edr", // primary identity detection that opens the ticket; control-plane only, no EDR to pivot to
      description:
        "A second, non-interactive Entra sign-in for m.delgado from 91.132.139.204 in Frankfurt (AS51167) on Chrome 121 — multifactor satisfied by a claim in the token.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "d61a4f08-2e93-4c57-b8d0-45a1c9f36e72",
        "azure.signinlogs.properties.createdDateTime": T(12 * MIN + 3 * SEC),
        "azure.signinlogs.properties.userPrincipalName": victim,
        "azure.signinlogs.properties.userDisplayName": "Maria Delgado",
        "azure.signinlogs.properties.userId": "b8f42a09-6d31-4c7e-9a15-3e0c8b71d4f2",
        "azure.signinlogs.properties.correlationId": "8b05d7c4-1a69-4e38-9f27-c40e6b91a53d",
        "azure.signinlogs.properties.sessionId": sessionId,
        "azure.signinlogs.properties.appDisplayName": "Microsoft Office",
        "azure.signinlogs.properties.appId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "azure.signinlogs.properties.resourceDisplayName": "Microsoft Graph",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.isInteractive": false,
        "azure.signinlogs.properties.ipAddress": replayIp,
        "azure.signinlogs.properties.autonomousSystemNumber": 51167,
        "azure.signinlogs.properties.location.city": "Frankfurt am Main",
        "azure.signinlogs.properties.location.state": "Hesse",
        "azure.signinlogs.properties.location.countryOrRegion": "DE",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 50.1109,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": 8.6821,
        "azure.signinlogs.properties.deviceDetail.deviceId": "",
        "azure.signinlogs.properties.deviceDetail.displayName": "",
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 10",
        "azure.signinlogs.properties.deviceDetail.browser": "Chrome 121.0.6167",
        "azure.signinlogs.properties.deviceDetail.isCompliant": false,
        "azure.signinlogs.properties.deviceDetail.isManaged": false,
        "azure.signinlogs.properties.deviceDetail.trustType": "",
        "azure.signinlogs.properties.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.authenticationDetails": [
          {
            authenticationStepDateTime: T(12 * MIN + 3 * SEC),
            authenticationMethod: "Previously satisfied",
            authenticationMethodDetail: "",
            succeeded: true,
            authenticationStepResultDetail: "MFA requirement satisfied by claim in the token",
            authenticationStepRequirement: "Multifactor authentication",
          },
        ],
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.appliedConditionalAccessPolicies": [
          {
            id: "1f0b6c93-7d24-4a5e-8b90-c3f27a641e58",
            displayName: "Require MFA for all users",
            result: "success",
            enforcedGrantControls: ["Mfa"],
            enforcedSessionControls: [],
          },
        ],
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.riskDetail": "none",
        "azure.signinlogs.properties.riskState": "none",
        "azure.signinlogs.properties.riskEventTypes_v2": [],
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "none",
        "azure.signinlogs.properties.status.errorCode": 0,
        "azure.signinlogs.resultType": "0",
      },
    },

    // ── 10. The replayed session brokers a mailbox token ─────────────────────
    {
      id: "aitm_10_exo_token",
      ts: T(12 * MIN + 20 * SEC),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "auth_success", severity: "high", mitre_technique: "T1550.004",
      user_email: victim,
      src_ip: replayIp,
      geo: { country: "Germany", city: "Frankfurt", latitude: 50.1109, longitude: 8.6821 },
      description:
        "A non-interactive token for Office 365 Exchange Online was issued to the OWA app from 91.132.139.204, again with no authentication step performed.",
      raw: {
        "azure.signinlogs.category": "NonInteractiveUserSignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "3fa9c105-77be-4d28-a640-9c15e8b03d7a",
        "azure.signinlogs.properties.createdDateTime": T(12 * MIN + 20 * SEC),
        "azure.signinlogs.properties.userPrincipalName": victim,
        "azure.signinlogs.properties.userId": "b8f42a09-6d31-4c7e-9a15-3e0c8b71d4f2",
        "azure.signinlogs.properties.correlationId": "8b05d7c4-1a69-4e38-9f27-c40e6b91a53d",
        "azure.signinlogs.properties.sessionId": sessionId,
        "azure.signinlogs.properties.appDisplayName": "OWA",
        "azure.signinlogs.properties.appId": "5d661950-3475-41cd-a2c3-d671a3162bc1",
        "azure.signinlogs.properties.resourceDisplayName": "Office 365 Exchange Online",
        "azure.signinlogs.properties.resourceId": "00000002-0000-0ff1-ce00-000000000000",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.isInteractive": false,
        "azure.signinlogs.properties.ipAddress": replayIp,
        "azure.signinlogs.properties.autonomousSystemNumber": 51167,
        "azure.signinlogs.properties.location.city": "Frankfurt am Main",
        "azure.signinlogs.properties.location.countryOrRegion": "DE",
        "azure.signinlogs.properties.deviceDetail.deviceId": "",
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 10",
        "azure.signinlogs.properties.deviceDetail.browser": "Chrome 121.0.6167",
        "azure.signinlogs.properties.deviceDetail.isCompliant": false,
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.authenticationDetails": [
          {
            authenticationStepDateTime: T(12 * MIN + 20 * SEC),
            authenticationMethod: "Previously satisfied",
            succeeded: true,
            authenticationStepResultDetail: "MFA requirement satisfied by claim in the token",
            authenticationStepRequirement: "Multifactor authentication",
          },
        ],
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "none",
        "azure.signinlogs.properties.status.errorCode": 0,
        "azure.signinlogs.resultType": "0",
      },
    },

    // ── 11. Mailbox read on the hijacked session ─────────────────────────────
    {
      id: "aitm_11_mail_access",
      ts: T(13 * MIN + 47 * SEC),
      source: "o365", vendor: "Microsoft 365 Unified Audit Log",
      event_type: "cloud_api_call", severity: "high", mitre_technique: "T1114",
      user_email: victim,
      src_ip: replayIp,
      geo: { country: "Germany", city: "Frankfurt" },
      cloud: { provider: "Microsoft", service: "Exchange Online", api_call: "MailItemsAccessed", resource: "m.delgado@nexacorp.com" },
      description:
        "The Unified Audit Log recorded a MailItemsAccessed bind against m.delgado's Inbox from 91.132.139.204, client string Client=OWA;Action=ViaProxy.",
      raw: {
        "data.office365.Operation": "MailItemsAccessed",
        "data.office365.RecordType": "50",
        "data.office365.Workload": "Exchange",
        "data.office365.UserId": victim,
        "data.office365.UserType": "0",
        "data.office365.ResultStatus": "Succeeded",
        "data.office365.ClientIPAddress": replayIp,
        "data.office365.ClientInfoString": "Client=OWA;Action=ViaProxy",
        "data.office365.MailboxOwnerUPN": victim,
        "data.office365.MailboxGuid": "6f0d2a41-c8b3-4e97-95d1-7a2e40cb8365",
        "data.office365.LogonType": "0",
        "data.office365.ExternalAccess": "false",
        "data.office365.MailAccessType": "Bind",
        "data.office365.SessionId": sessionId,
        "data.office365.OrganizationId": "a7b8c9d0-1234-5678-abcd-ef0123456789",
        "data.office365.Folders[0].Path": "\\Inbox",
        "data.office365.Folders[0].FolderItems[0].InternetMessageId": "<CH2PR12MB4901A7E3F02D9C1B4@CH2PR12MB4901.namprd12.prod.outlook.com>",
        "event.action": "MailItemsAccessed",
        "event.outcome": "success",
        "source.ip": replayIp,
      },
    },

    // ── 12. Persistence — attacker registers their own MFA method ────────────
    {
      id: "aitm_12_mfa_register",
      ts: T(19 * MIN),
      source: "o365", vendor: "Microsoft Entra ID",
      event_type: "account_modify", severity: "critical", mitre_technique: "T1098.005",
      user_email: victim,
      src_ip: replayIp,
      geo: { country: "Germany", city: "Frankfurt" },
      description:
        "A second Microsoft Authenticator method was registered on m.delgado's account from 91.132.139.204 — initiator and target are the same user, with no directory role in use.",
      raw: {
        "azure.auditlogs.category": "AuditLogs",
        "azure.auditlogs.operationName": "User registered security info",
        "azure.auditlogs.properties.activityDisplayName": "User registered security info",
        "azure.auditlogs.properties.activityDateTime": T(19 * MIN),
        "azure.auditlogs.properties.category": "UserManagement",
        "azure.auditlogs.properties.loggedByService": "Authentication Methods",
        "azure.auditlogs.properties.operationType": "Update",
        "azure.auditlogs.properties.result": "success",
        "azure.auditlogs.properties.resultReason": "User registered security info: Microsoft Authenticator app",
        "azure.auditlogs.properties.correlationId": "8b05d7c4-1a69-4e38-9f27-c40e6b91a53d",
        "azure.auditlogs.properties.initiatedBy.user.userPrincipalName": victim,
        "azure.auditlogs.properties.initiatedBy.user.id": "b8f42a09-6d31-4c7e-9a15-3e0c8b71d4f2",
        "azure.auditlogs.properties.initiatedBy.user.ipAddress": replayIp,
        "azure.auditlogs.properties.initiatedBy.user.roles": [],
        "azure.auditlogs.properties.targetResources[0].type": "User",
        "azure.auditlogs.properties.targetResources[0].userPrincipalName": victim,
        "azure.auditlogs.properties.targetResources[0].id": "b8f42a09-6d31-4c7e-9a15-3e0c8b71d4f2",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "StrongAuthenticationMethod",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue": "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true},{\"MethodType\":\"PhoneAppNotification\",\"Default\":false}]",
        "event.action": "user-registered-security-info",
        "event.outcome": "success",
        "source.ip": replayIp,
      },
    },
  ];

  // Every event belongs to the one AiTM token-theft incident (correlation key;
  // also lets the EDR console associate the identity-plane case).
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Adversary-in-the-Middle Phishing — Session Token Theft", events, T, MIN, SEC, victim, proxyIp, replayIp, vpnEgress, phishHost, phishUrl };
}
