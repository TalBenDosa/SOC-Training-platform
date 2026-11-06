# Problems found in readings and graded tasks while building rooms 58+

Builders and reviewers may not change these: a reading edit disables its recorded narration, and a graded task needs a decision. Each line needs Tal's approval.

| Room | Task | Problem | Fix |
|---|---|---|---|
| defender-xdr | r1 (reading) | Lists tasklist and netstat as Live Response commands. The console's own commands are processes and connections. | Correct the list, re-record narration. |
| incident-response-methodology | la1 explanation | T1036.005 uses the old name "Match Legitimate Name or Location". | "Match Legitimate Resource Name or Location". |
| incident-response-methodology | q4 explanation | Says KRBTGT is reset twice "due to Active Directory replication". The reason is that the previous password stays valid. | Reword. |
| investigation-methodology | q3, r2 (reading) | Says NCSA logs are local time with no offset. NCSA carries a GMT offset; only the IIS format has none. | Make the source an IIS-format log, re-record narration. |
| investigation-methodology | r1 (reading) | Misplaced parenthesis in "anomalies (events that should not be there, or absences) events that should be there but are missing?". | Reword, re-record narration. |
| auth-identity-monitoring | q1 | "80 Event ID 4625 entries ... 75 different user accounts, each account attempted exactly once" does not add up. | "75 entries", or "once or twice". |
| auth-identity-monitoring | r1, la1 explanation | Gives 0xC0000234 as a SubStatus. Real 4625s usually carry it in Status with SubStatus 0x0. | Reword, re-record narration. |
| ioc-analysis, auth-identity-monitoring | r1, r2, la1, flag1 | 185.220.101.45 is in a real Tor range, and corp.com is a real domain. Part of the known platform-wide pass. | Replace with documentation values, together with the flag answer. |
| reporting-documentation | ac1 | attacker_dwell_minutes: 22 is the session length, but Reading 4 defines dwell as detection minus first compromise. | Rename the field or fix the value. |
| reporting-documentation | log-1 | 192.168.1.100 is treated as an external C2 address and blocked at the firewall, but it is a private address. | Use 203.0.113.x. |
| reporting-documentation | r2, r4 (readings) | MTTD and dwell time are defined as the same interval on one incident, and the readings never say so. | Reword, re-record narration. |
| nac-masterclass | la1 | message_code 5411 means "Supplicant stopped responding", but the event is a successful quarantine authorization (5200). Step 11507 is also an odd fit. | Fix the codes. |
| nac-masterclass | r10 (reading) | "Unexpected profiler event: device profile mismatch" does not look like a real ISE message. | Reword, re-record narration. |
| soar-automation | la1, la2, ac1 | Use real public addresses and real vendor names. | Replace with documentation values. |
| customer-communication | log-1 | source "siem", event_type "edr_alert" on an SLA record the context says the SOAR generated. | Align the fields. |
| nac-masterclass | r3 (reading) | Calls EAP-FAST "Cisco proprietary" (it is RFC 4851) and says it is "stronger than unprotected PEAP". | Reword, re-record narration. |
| soar-automation | ac1, flag1 | Names Zendesk and a routable AWS address in the graded scenario. | A fictional vendor and 203.0.113.x, with the flag wording. |
| reporting-documentation | r3 (reading) | Calls TheHive open source; version 5 is commercial with a free Community licence. | Reword, re-record narration. |
| customer-communication, reporting-documentation | ac1 | d.levy@globalfinance.com and p.nguyen@contoso.com use .com domains in graded events. | Use .example. |
| asset-context-prioritisation | r7 diagram, o1 | The diagram puts a medium alert on the payment system during launch at Priority 1, but o1's answer ranks the exec laptop first. | Fix the diagram (narration safe). |
| asset-context-prioritisation | r7 (reading) | Mentions benign-true-positive tasks "throughout this room"; there is one. | Reword, re-record narration. |
| google-workspace-security | readings, graded | gws.admin.oauth_tokens_revoked, gws.access.via_oauth_app, gws.token.access_type and gws.app.* are not native Reports API parameters. | Use native names (originating_app_id). |
| rmm-abuse-remote-access-tools | readings, r0 checkpoint | T1219 name: check against the repo's MITRE library ("Remote Access Tools" there, "Remote Access Software" in the room). r0 lists Quick Assist as third-party, though it is built into Windows. | Align. |
| rmm-abuse-remote-access-tools | la1, ac1 | Public-looking IPs and cascadiafreight.com. | Replace with documentation values. |
| google-workspace-security | r7, la1 context | "A third-party app granted sensitive scopes" is presented as a built-in Alert Center type; it is not in Google's list. | Word it as a custom activity rule. |
| google-workspace-security | r4, r6, q2, q4 | gws.token.access_type and gws.admin.oauth_tokens_revoked have no native source, and q2 and q4 turn on them. | State they are enrichment, or use the token log's revoke and activity events. |
| google-workspace-security | r4 (reading) | "Only valid while a live session exists": an online access token works until it expires; it just cannot be refreshed. | Reword, re-record narration. |
| google-workspace-security | ac1 | expected_verdict "fp" contradicts correct_verdict benign_true_positive. | Align the event data. |
| google-workspace-security | la1, la2, ac1 | Real company (Grammarly), routable IPs, non-.example domains. | Replace with fictional values. |
| ot-ics-security | la1, ac1 | zeek.modbus.address shows 40020 and 40030 (4xxxx notation); the wire address Zeek reports would be 19 and 29. | Align the values. |
| use-case-development | m1, log-1 | m1 maps encoded PowerShell to T1027.010, log-1 tags the same behaviour T1059.001. | Explain or align. |
| data-staging-exfiltration-channels | la1 | data.rcvdbyte 88,240 is too low for 796 MB sent. | Use a realistic value. |
| data-staging-exfiltration-channels | la1, ac1 | data.eventtime decodes to 2026-08-01, but ts says 22 and 23 July. | Align the timestamps. |
| data-staging-exfiltration-channels | r4 (reading) | Talks about matching "400MB read" to an archive, but Event ID 5145 has no byte field. | Reword, re-record narration. |
| ot-ics-security | f1, q2, q4, r2-r5, r4 checkpoint | T0855 and T0812 were revoked in ATT&CK v19.0 (replaced by T1692.001 and T1694.001). The flag answer is T0855. Also in newTopicLessons.ts and otNetworkAnomaly.ts. | Move to the new IDs, accept both on f1, re-record narration. |
| dns-deep-dive | la1 | Description says "214 DNS TXT/NULL queries", context says 168 of 214 are TXT. | Reword. |
| dns-deep-dive | qf1 | "5–15 minutes" has an en dash. | "5 to 15 minutes". |
| kerberos-authentication | r3 (reading) | Says an account with msDS-SupportedEncryptionTypes unset produces 0x17; since the April 2026 RC4 hardening the default is AES for such accounts (check against Microsoft's KB). | Reword, re-record narration. |
| kerberos-authentication | graded 4769 events | TargetUserName without @REALM and IpAddress without ::ffff:. | Native format. |
| windows-protocols-lateral | m1 | Tests WinRM 5985/5986 and RDP 3389, which no reading teaches; ties remote task creation to \PIPE\atsvc only. | Add to a reading or reword. |
| windows-protocols-lateral | r6 (reading) | Implies the PsExec payload runs as SYSTEM by default; without -s it runs as the connecting user. | Reword, re-record narration. |
| email-protocols-forensics | r1, la1 | r1's transcript shows no STARTTLS, but la1's top Received line says ESMTPS. | Align. |
| email-protocols-forensics | r5 (reading) | The sample bh= is the SHA-256 of an empty body. | Change the sample, re-record narration. |
| email-protocols-forensics | qf1, la2, graded data | Em dashes in qf1; real registrar NiceNIC; non-.example domains and 154.16.88.201. | Replace. |
| kerberos-authentication | r5 (reading) | "If you're looking at a 4769 for a service account's SPN, you're looking at Kerberoasting" is false as written: every ordinary use logs that event. | Reword, re-record narration. |
| tls-encrypted-traffic | qf1 explanation | Says the grouping catches a beacon that rotates its destination IP; by SourceIp, DestinationIp, JA3Hash does the opposite. | Correct the explanation. |
| tls-encrypted-traffic | qf1 blanks | Says any floor from 10 to 90 and stdev 5 to 20 is accepted, but the grader matches a list, so 35, 65, 11, 16 fail. | Fill the lists or grade numerically. |
| tls-encrypted-traffic | ac1 fp_trap | "contacted 244 times before" misreads a count of hosts. | "seen from 244 hosts". |
| tls-encrypted-traffic | la1, la2 | Public addresses and domains. | Replace. |
| windows-protocols-lateral | r1 (reading) | Says SMB signing is required by default on 24H2 and Server 2025; Server 2025 is outbound only. | Reword, re-record narration. |
| windows-protocols-lateral | la1, ac1 | AccessMask 0x120089 is read-only though the session drove svcctl; %%4432 is not a file right. | 0x12019F with a matching AccessList. |
| windows-protocols-lateral, tls-encrypted-traffic | qf1, kqlPrimer.ts | En and em dashes in learner text. | Replace. |
| memory-disk-forensics | la1, r4 | la1 sets all four $SI times to 2019 though SetFileTime cannot set the MFT-changed time; $UsnJrnl fields sit inside a Windows.NTFS.MFT record; "a copy gets a fresh creation time" does not hold for robocopy. | Reword or align. |
| edr-detection-investigation | la1, ac1, r2, r4 | ac1 ContextBaseFileName cmd.exe on a regsvr32 event; "Signed Binary Proxy Execution" is the old ATT&CK name; GrantedAccess vs DesiredAccess; old "Security Center" name. | Align. |
| ransomware-full-lifecycle | r2 (reading) | Broken sentence: "...is publicly disclosed for one of these devices. Real, well-documented examples include...". | Fix, re-record narration. |
| ransomware-full-lifecycle | la3, la2 | 07:12 minus twelve minutes puts task creation at the minute the tasks fire; gdrive-sync-relay.net is not reserved. | Align, replace. |
| threat-intelligence | la1 | first_seen 2024-12-13 with SUNBURST, public in December 2020. | Fix the date. |
| threat-intelligence | r2 (reading) | Lists Phosphorus under CrowdStrike's KITTEN names; expands TAXII as "Indicator Information" (2.x is "Intelligence Information"). | Reword, re-record narration. |
| edr-detection-investigation | r2, q4, la1, ac1 | "Detected, no action taken" is not a real PatternDispositionDescription; real values read "Detection, standard detection." and "Prevention, process killed." | Change source and labs together. |
| ransomware-full-lifecycle | m1 | Pair clearlog says "cleared right after the intrusion", against r6 and o1. | "cleared just before encryption". |
| ransomware-full-lifecycle | la1, la2, la3 | "Detected, no action taken" and "Detected, kill process" are not real Falcon strings. | Align in a platform-wide pass. |
