/**
 * Adversary-in-the-Middle Phishing — Session Token Theft (ADVANCED)
 *
 * Evilginx/Tycoon-style reverse-proxy phishing. The lesson is deliberately
 * uncomfortable: MFA was satisfied correctly, by the real user, on the real
 * identity provider — and the account fell anyway, because what the attacker
 * stole was the post-authentication session cookie, not the password.
 *
 * The discriminating evidence is findable, not narrated: one `sessionId`
 * appears on two Entra sign-ins six minutes apart, from two IPs in two
 * autonomous systems, with two different browser fingerprints — and the second
 * one carries `authenticationRequirement: "multiFactorAuthentication"` that the
 * user never performed.
 */
import type { IOC, ScenarioBundle, ScenarioQuestion, TelemetryEvent } from "@/lib/sim/types";

export function buildAitmTokenTheftScenario(scenarioId = "aitm-token-theft-2026"): ScenarioBundle {
  const B = new Date("2026-03-17T07:12:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // ── Cast ───────────────────────────────────────────────────────────────────
  const victim = "m.delgado@nexacorp.com";          // Financial Controller, standard user
  const traveller = "a.rosen@nexacorp.com";         // benign look-alike: real trip, real VPN

  // ── Infrastructure ─────────────────────────────────────────────────────────
  const corpEgress = "82.80.14.6";                  // Zscaler / Bezeq egress, Tel Aviv
  const proxyIp = "45.87.81.126";                   // reverse-proxy front end, Amsterdam (AS60068)
  const replayIp = "91.132.139.204";                // attacker workstation, Frankfurt (AS51167)
  const vpnEgress = "194.145.227.18";               // corporate VPN concentrator, Frankfurt (AS202422)
  const phishHost = "login.nexacorp-sso.com";
  const phishUrl = `https://${phishHost}/common/oauth2/v2.0/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca`;

  // One browser session, issued once, used twice. This is the whole scenario.
  const sessionId = "0f2c1e64-3b7a-4c19-9d84-5a6e2f8b17d3";

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
        "A mail claiming a vendor agreement needs signature was delivered to m.delgado. The display name reads 'NexaCorp IT Service Desk' but the envelope sender is on docu-sign-secure.com, and the embedded link points at login.nexacorp-sso.com — neither domain belongs to NexaCorp.",
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
        "pps.quarantineFolder": "",
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
      geo: { country: "Israel", city: "Tel Aviv", latitude: 32.0853, longitude: 34.7818 },
      network: { url: phishUrl, domain: phishHost, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92" },
      description:
        "URL Defense recorded m.delgado following the rewritten link four minutes after delivery. The click came from the Tel Aviv corporate egress on her own Edge browser, and the gateway permitted the destination.",
      raw: {
        "pps.clickTime": T(4 * MIN),
        "pps.QID": "4A2F91C037",
        "pps.messageID": "<f21c9a4e-7b03-4d16-8e5a-2c9047ab6631@docu-sign-secure.com>",
        "pps.recipient": victim,
        "pps.url": phishUrl,
        "pps.clickIP": corpEgress,
        "pps.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
        "pps.classification": "",
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
        "LT-FIN-0442 resolved login.nexacorp-sso.com. The answer is a single hosting-provider address in Amsterdam — NexaCorp's real sign-in traffic resolves to login.microsoftonline.com.",
      raw: {
        "infoblox.client_ip": "10.42.18.77",
        "infoblox.query_name": phishHost,
        "infoblox.query_type": "A",
        "infoblox.rcode": "NOERROR",
        "infoblox.answer": proxyIp,
        "infoblox.ttl": 300,
        "infoblox.view": "internal",
        "infoblox.member": "ns-tlv-01.nexacorp.com",
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
      geo: { country: "Israel", city: "Tel Aviv" },
      network: { url: phishUrl, domain: phishHost, method: "GET", status: 200, bytes_in: 48213, bytes_out: 1024 },
      description:
        "m.delgado's browser loaded the sign-in page from login.nexacorp-sso.com. Zscaler categorised the host as a newly registered domain and allowed it — the page it served is a proxy in front of the real Microsoft sign-in service.",
      raw: {
        "zscaler.login": victim,
        "zscaler.department": "Finance",
        "zscaler.location": "Tel Aviv HQ",
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
      geo: { country: "Israel", city: "Tel Aviv" },
      network: { url: `https://${phishHost}/common/login`, domain: phishHost, method: "POST", status: 302, bytes_in: 2211, bytes_out: 3874 },
      description:
        "A POST to /common/login on the look-alike host carried the form body from the fake sign-in page, and the proxy answered 302. Everything the user typed — and everything Microsoft sent back — passed through this host.",
      raw: {
        "zscaler.login": victim,
        "zscaler.department": "Finance",
        "zscaler.location": "Tel Aviv HQ",
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
        "Entra ID recorded a successful interactive sign-in for m.delgado with multifactor satisfied by a live Authenticator approval. The client address is the Amsterdam host she was posting to, not the Tel Aviv egress her own browser traffic came from.",
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
        "Nine seconds after the sign-in completed, the browser landed on the genuine www.office.com with the look-alike host as referer. From the user's seat the sign-in simply worked, which is why nothing was reported.",
      raw: {
        "zscaler.login": victim,
        "zscaler.location": "Tel Aviv HQ",
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
        "a.rosen signed in from Frankfurt while her baseline is Tel Aviv, which fired the same geo-change logic. Her record carries its own sessionId, a fresh Authenticator approval timed to this sign-in, an Entra-joined compliant device, and a named corporate VPN network location.",
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
      description:
        "A second Entra sign-in for m.delgado, six minutes after the first, carrying the identical sessionId 0f2c1e64-… from a different address, a different autonomous system and a different browser. No authentication step was performed — the multifactor requirement was met by a claim already inside the token.",
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
        "Seventeen seconds later the same session obtained a non-interactive token for Office 365 Exchange Online from the Frankfurt address, again with no authentication step performed.",
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
        "The Unified Audit Log recorded a mailbox bind against m.delgado's Inbox from the Frankfurt address, stamped with the same SessionId as the two Entra sign-ins.",
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
        "A second Microsoft Authenticator method was registered on m.delgado's own account from the Frankfurt address. The initiator and the target are the same standard user account, and the Entra audit record shows no directory role in use — self-service registration is a normal user right, which is exactly why this persistence step raises no privilege error.",
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

  const iocs: IOC[] = [
    { type: "domain", value: phishHost,                    first_seen: T(4 * MIN + 6 * SEC),  reputation: "malicious",  tags: ["look-alike", "newly-registered"] },
    { type: "url",    value: phishUrl,                     first_seen: T(4 * MIN),            reputation: "malicious",  tags: ["credential-harvest", "mail-lure"] },
    { type: "ip",     value: proxyIp,                      first_seen: T(4 * MIN + 6 * SEC),  reputation: "malicious",  tags: ["hosting", "as60068", "external"] },
    { type: "ip",     value: replayIp,                     first_seen: T(12 * MIN + 3 * SEC), reputation: "malicious",  tags: ["hosting", "as51167", "external"] },
    { type: "email",  value: "billing@docu-sign-secure.com", first_seen: T(0),                reputation: "malicious",  tags: ["sender", "dmarc-none"] },
    { type: "domain", value: "docu-sign-secure.com",       first_seen: T(0),                  reputation: "malicious",  tags: ["sender-domain", "look-alike"] },
    { type: "user",   value: victim,                       first_seen: T(0),                  reputation: "suspicious", tags: ["compromised-account", "finance"] },
    { type: "ip",     value: vpnEgress,                    first_seen: T(9 * MIN),            reputation: "clean",      tags: ["corporate-vpn", "named-location"] },
  ];

  const killchain = [
    { ts: T(0),                     phase: "Initial Access",      action: "Lure delivered to m.delgado from docu-sign-secure.com with a link to login.nexacorp-sso.com" },
    { ts: T(4 * MIN),               phase: "Initial Access",      action: "User follows the rewritten link; gateway permits the click" },
    { ts: T(4 * MIN + 9 * SEC),     phase: "Collection",          action: "Browser loads the reverse-proxy sign-in page (Zscaler category: Newly Registered Domains)" },
    { ts: T(5 * MIN + 41 * SEC),    phase: "Credential Access",   action: "Credentials and the live MFA response are relayed through the proxy to the real Microsoft endpoint" },
    { ts: T(6 * MIN + 3 * SEC),     phase: "Initial Access",      action: "Entra records a genuine interactive sign-in, MFA satisfied, sourced from the proxy in Amsterdam" },
    { ts: T(6 * MIN + 12 * SEC),    phase: "Defense Evasion",     action: "Victim redirected to the real office.com — the sign-in appears to have simply worked" },
    { ts: T(12 * MIN + 3 * SEC),    phase: "Lateral Movement",    action: "Stolen session cookie replayed from Frankfurt on the same sessionId; MFA satisfied by token claim" },
    { ts: T(12 * MIN + 20 * SEC),   phase: "Lateral Movement",    action: "Replayed session brokers a non-interactive token for Office 365 Exchange Online" },
    { ts: T(13 * MIN + 47 * SEC),   phase: "Collection",          action: "Mailbox bind against the Inbox recorded in the Unified Audit Log with the same SessionId" },
    { ts: T(19 * MIN),              phase: "Persistence",         action: "Second Authenticator method registered on the account by the account — survives a password reset" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 20,
      prompt: "Event aitm_06 is a successful, MFA-satisfied sign-in for m.delgado. What does its ipAddress field tell you when read against the proxy logs?",
      hint: "Compare the Entra client address with the address m.delgado's own browser traffic came from.",
      kind: "single",
      options: [
        { value: "a", label: "It is 45.87.81.126 in Amsterdam — the host her browser was posting the sign-in form to" },
        { value: "b", label: "It is 82.80.14.6 in Tel Aviv — the corporate egress, matching her own browsing traffic" },
        { value: "c", label: "It is 91.132.139.204 in Frankfurt — the host that reuses the session six minutes later" },
        { value: "d", label: "It is a Microsoft service address, because the request was relayed inside the tenant" },
      ],
      answer: "a",
      explanation:
        "Zscaler (aitm_04, aitm_05) shows the user's browser leaving from 82.80.14.6 in Tel Aviv, so option b describes where she really was — but that is not what Entra recorded. Entra saw 45.87.81.126, because in a reverse-proxy phish the identity provider talks to the proxy, not to the victim. Option c is the replay host, which appears later in aitm_09. Option d is not how Entra sign-in logging works: ipAddress is always the client that reached the token endpoint. The mismatch between where the user browsed from and where Entra saw the sign-in from is the first structural tell of AitM.",
    },
    {
      id: "q2", xp: 25,
      prompt: "Conditional Access required MFA, the user genuinely approved an Authenticator push, and the account was still taken over. Why did MFA not prevent this?",
      hint: "Ask what the attacker actually ended up holding at the end of the sign-in.",
      kind: "single",
      options: [
        { value: "a", label: "She approved a push she should have rejected, so the second factor was never really satisfied" },
        { value: "b", label: "Conditional Access was misconfigured and did not apply the MFA grant control to this app" },
        { value: "c", label: "The proxy relayed the live MFA response and kept the session cookie Entra issued afterwards" },
        { value: "d", label: "The Authenticator registration was weak, letting the attacker derive valid codes offline" },
      ],
      answer: "c",
      explanation:
        "Option a describes MFA fatigue, a different attack — here the push arrived while she was actively signing in, so approving it was the correct behaviour. Option b is contradicted by the evidence: aitm_06 shows appliedConditionalAccessPolicies 'Require MFA for all users' with result 'success' and enforcedGrantControls ['Mfa']. Option d is not a real property of push-based Authenticator. MFA is an authentication-time control; it says nothing about what happens to the artefact issued after authentication. The proxy sat in the middle, passed the challenge and response through untouched, and harvested the resulting session cookie — which is why aitm_09 needs no authentication step at all.",
    },
    {
      id: "q3", xp: 25,
      prompt: "Which pair of events, read together, proves a stolen session cookie was replayed rather than a second legitimate sign-in occurring?",
      hint: "Look for a field that should be unique to one browser on one machine.",
      kind: "single",
      options: [
        { value: "a", label: "aitm_02 and aitm_05 — the same look-alike URL appears in the click record and the proxy POST" },
        { value: "b", label: "aitm_06 and aitm_09 — one sessionId, two IPs, two autonomous systems, two browsers, six minutes" },
        { value: "c", label: "aitm_09 and aitm_11 — the mailbox bind follows the Frankfurt sign-in inside the same two minutes" },
        { value: "d", label: "aitm_06 and aitm_08 — a Tel Aviv baseline user appearing in Europe twice in the same window" },
      ],
      answer: "b",
      explanation:
        "Option a only proves the user visited the phishing site; it says nothing about what happened to the session afterwards. Option c is real follow-on activity but is equally consistent with the attacker having simply logged in with a stolen password. Option d compares two different people — aitm_08 is a.rosen, not m.delgado. Only aitm_06 and aitm_09 carry the identical sessionId 0f2c1e64-3b7a-4c19-9d84-5a6e2f8b17d3 while disagreeing on ipAddress (45.87.81.126 vs 91.132.139.204), autonomousSystemNumber (60068 vs 51167) and deviceDetail.browser (Edge 122 vs Chrome 121). One session identifier cannot legitimately be held by two browsers on two machines 365 km apart six minutes apart. The second record also has isInteractive: false and authenticationStepResultDetail 'MFA requirement satisfied by claim in the token' — nobody authenticated.",
    },
    {
      id: "q4", xp: 20,
      prompt: "aitm_08 shows a.rosen signing in from Frankfurt against a Tel Aviv baseline, which fired the same geo-change logic. What separates it from the replay in aitm_09?",
      hint: "Both records are in Germany. Look at what each one had to do to get its MFA claim.",
      kind: "single",
      options: [
        { value: "a", label: "It has its own sessionId and a fresh Authenticator approval on a compliant Entra-joined device" },
        { value: "b", label: "It is a lower-severity record, and Entra assigned it no sign-in risk during authentication" },
        { value: "c", label: "It comes from Germany, which is allow-listed, while the replay came from the Netherlands" },
        { value: "d", label: "It is an interactive sign-in, and interactive sign-ins can never come from a replayed cookie" },
      ],
      answer: "a",
      explanation:
        "Option b is a trap: riskLevelDuringSignIn is 'none' on aitm_09 too, so risk scoring does not discriminate here at all — that is part of the lesson. Option c is factually wrong; the replay in aitm_09 is also in Frankfurt, Germany. Only the proxy front end (aitm_06) was in the Netherlands, and geography alone never separates these cases. Option d overstates a true fact — an attacker can drive an interactive browser session, so isInteractive is supporting evidence, not proof. The real discriminators on aitm_08 are structural: a distinct sessionId, two authenticationDetails entries with timestamps seconds before the sign-in (a second factor actually performed), deviceDetail.isCompliant true with trustType 'Azure AD joined', and a networkLocationDetails entry naming the corporate VPN. aitm_09 has none of these.",
    },
    {
      id: "q5", xp: 20,
      prompt: "Containment has been approved. Which action set actually removes the attacker's access in this incident?",
      hint: "Two artefacts here outlive a password change.",
      kind: "single",
      options: [
        { value: "a", label: "Reset the password, then have the user re-approve MFA on her phone to restore a trusted session" },
        { value: "b", label: "Block 91.132.139.204 at the perimeter and purge the lure message from every mailbox in the tenant" },
        { value: "c", label: "Revoke refresh tokens and sessions, delete the attacker-registered method, then reset the password" },
        { value: "d", label: "Disable the account for 24 hours and re-enable it once the look-alike domain has been taken down" },
      ],
      answer: "c",
      explanation:
        "Option a fails on both artefacts: a password reset does not invalidate an already-issued session cookie, and the extra Authenticator method registered in aitm_12 stays on the account afterwards, letting the attacker complete MFA on a future sign-in. Option b is useful hygiene but the attacker simply moves to another host; IP blocking does not touch the stolen token. Option d buys time and then hands the account back with the rogue method still enrolled. The correct order is revoke first (this is what kills the live session), then remove the registered authentication method, then reset the password — and only afterwards review sign-in logs for any other session that shares sessionId 0f2c1e64-….",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Adversary-in-the-Middle Phishing — Session Token Theft",
    threat_actor: "Storm-1167 (AitM phishing-as-a-service operator)",
    attack_kind: "aitm_session_hijack",
    narrative:
      "A finance controller receives a signature-request lure and follows it to login.nexacorp-sso.com, a look-alike host fronting a reverse proxy. She types her password and approves a genuine Microsoft Authenticator push — the sign-in really does complete, MFA really is satisfied, and Conditional Access really does pass. The proxy relays every step to the real Microsoft endpoint and keeps the session cookie Entra issues at the end. Six minutes later that same session identifier reappears from a hosting provider in Frankfurt, on a different browser, in a different autonomous system, with no authentication step performed: the multifactor requirement is satisfied by a claim already inside the token. The attacker brokers a mailbox token, reads the Inbox, and registers a second Authenticator method on the account — a normal self-service action for a standard user, and one that survives the password reset the SOC is about to order. A colleague signing in from Frankfurt on the corporate VPN the same morning trips the same geo-change logic and is entirely benign.",
    learning_objectives: [
      "Trace an AitM reverse-proxy chain from the mail lure through the look-alike domain to a genuine Entra sign-in whose client address is the proxy, not the user",
      "Explain why a satisfied multifactor requirement did not prevent the compromise, and what MFA does and does not protect",
      "Correlate two Entra sign-in records on a shared session identifier to prove session-cookie replay rather than a second legitimate logon",
      "Discriminate token replay from an ordinary travel or VPN geo change using session, authentication-step and device-compliance evidence",
      "Select containment that invalidates the stolen session and removes the attacker-registered authentication method, not just the password",
    ],
    alerts: [], // alerts are attached by the catalogue wiring
    events,
    iocs,
    killchain,
    questions,
  };
}
