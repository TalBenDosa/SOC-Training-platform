# XDR investigation console for Team Training

Owner's request: a Team Training session can run on a KQL investigation console, chosen before the session starts, end to end, including KQL over the scenario's data. When chosen, a detection raises an incident in the console instead of an EDR alert. When not chosen, nothing changes.

**Name and design (owner, 2026-11-08).** The console first imitated Microsoft Sentinel in the Azure portal closely. To stay clear of copyright and trade dress, it is now **XDR**, this platform's own product: its own name, wordmark, header, menu, palette and graph language. It collects the organization's Microsoft 365, Defender and identity telemetry in one place, raises incidents and lets the team query with KQL. It does not claim to be Microsoft's product or to run in Azure.

- User-visible name: "XDR" everywhere (Session Builder "XDR console (KQL)", "Investigate in XDR", "Open XDR", tours, role guide, notices, activity log, report line, tab title, header).
- Route: `/xdr?team=<id>&u=&r=&incident=&host=`. `/sentinel` redirects to `/xdr` with the same query (old links and windows), `src/app/(app)/sentinel/page.tsx` and `xdrHref` in `src/lib/team/twoWindows.ts`.
- Internal identifiers keep the old name to avoid churn: `src/lib/sentinel`, `src/components/sentinel`, event types `sentinel.*`, `team_sessions.config.console = "sentinel"`, CSS prefix `st-`, window and channel names `sentinel-<id>`.
- Product names: alerts raised by the console's own analytics read `ProductName = "XDR Analytics"`, `ProviderName = "XDR Scheduled Alerts"`; `SecurityIncident.ProviderName` and `ModifiedBy` are `XDR`; the incident activity log writes as `XDR`. Source products keep their real names (Microsoft Defender for Endpoint, Entra ID Protection, Defender for Office 365, Defender for Cloud Apps, GuardDuty...): they are the data, not the console. KQL table and column names (SigninLogs, DeviceProcessEvents, SecurityAlert, SecurityIncident...) stay: they are the data model analysts query. `src/lib/sentinel/xdrBrand.ts` renames what the workspace shows and what the team room of an XDR session shows (feed rows and their native views); stored payloads are unchanged.
- Design: a dark console in HACK THE SOC's palette (theme tokens `--cyber-*`, `--on-accent`), the app's fonts (Inter, JetBrains Mono), XDR wordmark header with workspace and session chips, a menu grouped Investigate / Context / Workspace with lucide icons, page headers inside the page, rounded cards, pill tabs and filters, a toolbar command bar, its own severity colours (each 4.5:1 or more on every surface, the word always beside the colour), hexagon alert nodes and rounded-square entity nodes in the graph. No Segoe UI, no Fluent blue, no portal breadcrumb.

## Architecture

```
session_events (feed.event, public payloads, RLS: members only)
   |  useTeamSentinel(sessionId) polls every 6s, same rebased times as the feed
   v
TelemetryEvent[] released so far
   |  buildWorkspace()  src/lib/sentinel/workspace.ts
   |    nativize() -> native record -> Log Analytics row (real table, real columns)
   |    use cases + product detections -> SecurityAlert -> grouped into incidents
   |    xdrValue(): the console's own name on every row, alert and incident
   v
SentinelWorkspace (tables, alerts, incidents, entities, rules, hunting)
   |  runKql()  src/lib/kql
   v
SentinelConsole  src/components/sentinel  (route /xdr?team=<id>)
   |  SentinelActions -> apply_session_action (sentinel.*, edr.host_isolated)
   v
session_events -> folded into IncidentState, shared by the team -> after-action report
```

Contract: `src/lib/kql/types.ts`, `src/lib/sentinel/types.ts`.

## Graph alerts in the SIEM feed

An XDR session's stack carries `detection_feed: "ms_graph"` (set by `stackForConsole`, kept by `sanitizeStack`, no choice in the picker). In the feed, a product detection of a Microsoft product then renders as its Microsoft Graph Security alert (`src/lib/logs/native/sources/ms_graph.ts`, card `docs/log-schemas/siem-ms-graph-alerts.md`) and its row says Microsoft Graph Security. An alert of the SIEM's own analytics renders as `productName: "XDR Analytics"`, `serviceSource: "unknown"` (XDR is not a Microsoft service). Raw logs keep their format. The public payload does not change: no new events, same queue, timing and scoring. The workspace reads each log's own record, so the hooks in `src/lib/team` pass it the stack without the key; `graphAlertFor(ev, companyId, stack, identity)` in `src/lib/logs/native` gives it the Graph alert of an event.

## Rules

- The workspace holds only what has reached the feed so far. A query can never see the future of the exercise.
- No answer data, ever: the input is the public payload. The console never reads session_injects.
- An incident must not mean "this is the attack". Benign activity raises incidents too, as real rules do.
- XDR is for deep investigation (owner, 2026-11-07). An incident opens only for linked alerts, for one high-severity alert with activity around it, for command-and-control or impact alerts, or when an analyst escalates a log. Any other alert stays a SecurityAlert row. Every released log stays queryable in KQL.
- Every table and column exists in the real data sources. Sources: Azure Monitor table reference, Defender XDR advanced hunting schema.
- Documentation IPs and fictional names only, as everywhere on the platform. No Microsoft logo, trademarked icon or portal look. Nothing in an XDR session names the console Microsoft Sentinel or Azure Sentinel (tests: `src/components/sentinel/XdrNaming.render.test.ts`, `src/app/(app)/team/[id]/_components/XdrNaming.render.test.ts`, `src/app/(app)/sentinel/redirect.test.ts`).
- English UI, no em dashes.
