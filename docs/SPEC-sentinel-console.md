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

## Rules

- The workspace holds only what has reached the feed so far. A query can never see the future of the exercise.
- No answer data, ever: the input is the public payload. The console never reads session_injects.
- An incident must not mean "this is the attack". Benign activity raises incidents too, as real rules do.
- Sentinel is for deep investigation (owner, 2026-11-07). An incident opens only for linked alerts, for one high-severity alert with activity around it, for command-and-control or impact alerts, or when an analyst escalates a log. Any other alert stays a SecurityAlert row. Every released log stays queryable in KQL.
- Every table and column exists in the real product. Sources: Azure Monitor table reference, Defender XDR advanced hunting schema.
- Documentation IPs and fictional names only, as everywhere on the platform. No Microsoft logo or trademarked icon. The word Sentinel is used because the owner asked for it by name.
- English UI, no em dashes.
