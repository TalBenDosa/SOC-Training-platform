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
