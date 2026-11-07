# Sentinel investigation console for Team Training

Owner's request: a Team Training session can run on Microsoft Sentinel, chosen before the session starts, with an interface very close to the real one, end to end, including KQL over the scenario's data. When chosen, a detection raises a Sentinel incident instead of an EDR alert. When not chosen, nothing changes.

References: `docs/ui-reference/real-console-ui.md` section 4; learn.microsoft.com/en-us/azure/sentinel/investigate-incidents and /incident-investigation.

## Architecture

```
session_events (feed.event, public payloads, RLS: members only)
   |  useTeamWorkspace(sessionId) polls every 6s, same rebased times as the feed
   v
TelemetryEvent[] released so far
   |  buildWorkspace()  src/lib/sentinel/workspace.ts
   |    nativize() -> native record -> Log Analytics row (real table, real columns)
   |    use cases + product detections -> SecurityAlert -> grouped into incidents
   v
SentinelWorkspace (tables, alerts, incidents, entities, rules, hunting)
   |  runKql()  src/lib/kql
   v
SentinelConsole  src/components/sentinel  (route /sentinel?team=<id>)
   |  SentinelActions -> apply_session_action (sentinel.*, edr.host_isolated)
   v
session_events -> folded into IncidentState, shared by the team -> after-action report
```

Contract: `src/lib/kql/types.ts`, `src/lib/sentinel/types.ts`.

## Graph alerts in the SIEM feed

A Sentinel session's stack carries `detection_feed: "ms_graph"` (set by `stackForConsole`, kept by `sanitizeStack`, no choice in the picker). In the feed, a product detection of a Microsoft product then renders as its Microsoft Graph Security alert (`src/lib/logs/native/sources/ms_graph.ts`, card `docs/log-schemas/siem-ms-graph-alerts.md`) and its row says Microsoft Graph Security. Raw logs keep their format. The public payload does not change: no new events, same queue, timing and scoring. The workspace reads each log's own record, so the hooks in `src/lib/team` pass it the stack without the key; `graphAlertFor(ev, companyId, stack, identity)` in `src/lib/logs/native` gives it the Graph alert of an event.

## Rules

- The workspace holds only what has reached the feed so far. A query can never see the future of the exercise.
- No answer data, ever: the input is the public payload. The console never reads session_injects.
- An incident must not mean "this is the attack". Benign activity raises incidents too, as real rules do.
- Sentinel is for deep investigation (owner, 2026-11-07). An incident opens only for linked alerts, for one high-severity alert with activity around it, for command-and-control or impact alerts, or when an analyst escalates a log. Any other alert stays a SecurityAlert row. Every released log stays queryable in KQL.
- Every table and column exists in the real product. Sources: Azure Monitor table reference, Defender XDR advanced hunting schema.
- Documentation IPs and fictional names only, as everywhere on the platform. No Microsoft logo or trademarked icon. The word Sentinel is used because the owner asked for it by name.
- English UI, no em dashes.
