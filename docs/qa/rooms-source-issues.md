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
| cloud-security-monitoring | la1, r2 (reading) | GuardDuty finding PrivilegeEscalation:IAMUser/AdministrativePermissions is retired; r2 lists GetObject without saying it is a data event, off by default. | Reword, re-record narration. |
| credential-attacks-practice | la1, la2 | la2 gives a 4-attempt lockout policy, but la1's answer says the limit may not have been reached after 47 attempts. | Align. |
| playbook-execution-and-escalation | q2 | Comes before r3, which teaches it; calls stopping a "deviation", but r3 says it is not one; stray colon in the question. | Reword or move. |
| playbook-execution-and-escalation | la1, graded data | "Hosting-provider network" is not in the record; routable 45.135.232.71, AS200651, northvale.com. | Replace. |
| escalation-procedures | log-1 | "P1 SLA: 15 min, 3 min breach" only works if the clock starts at acknowledgement; room 64 starts it at confirmation. | Align. |
| credential-attacks-practice | qf1 | Blank lists reject valid answers: window rejects 3h and 4h, threshold rejects 6, 7, 12, 60. | Add values or state the window and baseline. |
| playbook-execution-and-escalation | ac1 fp_trap | Discusses Step 4 and waiting until 07:00, but the learner only sees generic verdict cards. | Rewrite around the cards. |
| cloud-security-monitoring | r2, la1 | Exfiltration:S3/ObjectRead.Unusual is also retired; "PutBucketAcl making a bucket world-readable": on a bucket, ACL READ only lists objects. | Use AnomalousBehavior findings; name the object ACL or bucket policy step. |
| remote-email-collection | r2, r5, la1, m1 | Says phones produce Sync (only desktop Outlook does); la1 says the record repeats 24 times (Exchange rolls Binds into one record with OperationCount); m1 says New-InboxRule logs any rule (UpdateInboxRules also). | Reword, re-record narration. |
| remote-email-collection | graded data | northgate-logistics.com and 154.16.93.211. | Replace. |
| device-registration-persistence | r2 (reading), q4 | Register device logs under category Device, not DeviceManagement; q4's policy needs compliant or hybrid-joined, which a plain registered device is not. | Reword, re-record narration. |
| incident-report-writing | wr1 | Visible rubric says at least one real fact, but the grader needs 2 of 4 referenceIocs and scores only word count and identifiers. | Align rubric and grader. |
| incident-report-writing | r2, o1, la1 | r2 lists IOCs before the timeline, o1 the reverse; solstice-actuarial.com, 203.14.88.9; TaskName top-level. | Align. |
| investigate-alert-workflow | ac1 | FolderPath has no file name. | Add it. |
| remote-email-collection | r3 (reading), m1 redirectto, qf1 param2 | Says RedirectTo never delivers to the original mailbox and keeps no copy. False: a copy stays; redirect keeps the original sender. Graded on the false version. | Reword, re-record narration. High. |
| device-registration-persistence | r2, m1, la1, ac1 | modifiedProperties on 'User registered security info'; the diff really sits on an Update user record with the same correlationId. | Move it, update labs. |
| incident-report-writing | la1, f1 | TaskName shown as a top-level field; DeviceEvents holds it in AdditionalFields. FolderPath omits the file name. | Align. |
| investigate-alert-workflow | ac1, r4, q3 | FileCreated names powershell.exe, but rar.exe writes the archive; "Archive Collected Data via Utility" is not the ATT&CK name. | Align. |
| incident-report-writing | ac1 | 203.14.88.9, AS 14618, .com domains. | Replace. |
| vishing-helpdesk-social-engineering | la1, ac1 | Reset password (by admin) paired with loggedByService Core Directory; Microsoft lists it under Self-service Password Management; la1's explanation leans on it. | Align. |
| okta-identity-fundamentals | r8, r6 checkpoint, r2 | policy.rule.create is not in Okta's catalog (policy.rule.add is); user.mfa.okta_verify.push_response is not either. | Reword, re-record narration. |
| okta-identity-fundamentals | r3, q1, q5, la2, q3 | user.session.start SUCCESS does not prove a usable session; INVALID_CREDENTIALS is not necessarily a wrong password; q3 says five minutes, la2 seven, real gap 6m21s. | Align. |
| okta-identity-fundamentals | la1, la2 | 185.220.101.44, Alexhost SRL AS200019. | Replace. |
| threat-hunting-fundamentals | la1 | Command line lacks the comma after comsvcs.dll; a KQL query against Falcon data. | Fix. |
| vishing-helpdesk-social-engineering | ac1, r3, m1 | Agent re-registers MFA with only Helpdesk Administrator; "Cisco August 2022" is the disclosure date (compromise May 2022). | Align. |
| okta-identity-fundamentals | la2 | A stale Group Administrator role "made the change possible" for adding to Okta-Admins, but only super admins can manage groups with admin roles. | Make it Super Administrator or a non-admin group. |
| okta-identity-fundamentals | la1, r7 (reading) | asNumber should be a bare number; "the leading system. segment signals Okta's own infrastructure" contradicts system.api_token.create. | Fix, re-record narration. |
| ai-attacks-soc-social | la1 | EndpointMetaData.ActivityType and DestinationDomain are not in Microsoft's documented EndpointMetadata. | Correct with the source. |
| privileged-access-monitoring | r1b, r2, la2 | r1b shows internal ids (priv-r2, priv-r3's Step 6); r2 says only specific Windows processes access LSASS; sql.database_role carries a server role. | Reword, re-record narration. |
| detection-engineering | la1 | 91.108.56.177; event_type edr_alert on a SIEM correlation alert. | Replace. |
| edge-case-usecases | la1, la3, ac1 | la1 q1 cites crowdstrike.FileSigned, not in the record; la1, la3 descriptions give the answer away; severity mismatch; ac1 says MFA valid with no MFA field. | Fix. High for the answer leak. |
| tunneling-c2-channels | la1, la2, ac1, r1 | Real person Simon Tatham; routable addresses; attacker-server.com. | Replace. |
| privileged-access-monitoring | ac1, r4 | "3:22 AM Saturday" but the ts is a Sunday; Sysmon 1 described with 4688 field names. | Fix. |
| privileged-access-monitoring, detection-engineering | la1 explanations | En dashes in graded explanations. | Use "to". |
| edge-case-usecases | la1, ac3 | parent_name npm.cmd is never a process image; mde.SHA256 has 63 hex characters. | Correct. |
