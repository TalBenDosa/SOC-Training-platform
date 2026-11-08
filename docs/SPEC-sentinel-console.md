# XDR investigation console for Team Training

Owner's request: a Team Training session can run on a KQL investigation console, chosen before the session starts, end to end, including KQL over the scenario's data. When chosen, a detection raises an incident in the console instead of an EDR alert. When not chosen, nothing changes.

**Name and design (owner, 2026-11-08).** The console first imitated Microsoft Sentinel in the Azure portal closely. To stay clear of copyright and trade dress, it is now **XDR**, this platform's own product: its own name, and its own drawing of the graph, alerts and entities. It collects the organization's Microsoft 365, Defender and identity telemetry in one place, raises incidents and lets the team query with KQL. It does not claim to be Microsoft's product or to run in Azure.

- User-visible name: "XDR" everywhere (Session Builder "XDR console (KQL)", "Investigate in XDR", "Open XDR", tours, role guide, notices, the team room's activity log, report line, tab title, header).
- Route: `/xdr?team=<id>&u=&r=&incident=&host=`. `/sentinel` redirects to `/xdr` with the same query (old links and windows), `src/app/(app)/sentinel/page.tsx` and `xdrHref` in `src/lib/team/twoWindows.ts`.
- Internal identifiers keep the old name to avoid churn: `src/lib/sentinel`, `src/components/sentinel`, event types `sentinel.*`, `team_sessions.config.console = "sentinel"`, CSS prefix `st-`, window and channel names `sentinel-<id>`.
- Product names: alerts raised by the console's own analytics read `ProductName = "XDR Analytics"`, `ProviderName = "XDR Scheduled Alerts"`; `SecurityIncident.ProviderName` and `ModifiedBy` are `XDR`; an incident's case history writes as `XDR`. Source products keep their real names (Microsoft Defender for Endpoint, Entra ID Protection, Defender for Office 365, Defender for Cloud Apps, GuardDuty...): they are the data, not the console. KQL table and column names (SigninLogs, DeviceProcessEvents, SecurityAlert, SecurityIncident...) stay: they are the data model analysts query. `src/lib/sentinel/xdrBrand.ts` renames what the workspace shows and what the team room of an XDR session shows (feed rows and their native views); stored payloads are unchanged.
- Design (owner, 2026-11-08, second decision): the light console layout stays (header bar, grouped menu, count cards, grids, previews, flyouts). Three areas are drawn XDR's own way so they are not one-to-one with Sentinel: the investigation graph (alerts as cards with a severity side stripe on a central lane, entities as rounded tiles with icon and label inside, right-angled links with small arrowheads, an Events chip per alert, labelled question links, a grid canvas, a legend, a zoom group, tabs on top of the side pane), alerts (cards with a severity stripe, the time on the right, severity, product and MITRE tactic chips and key entities as chips; the alert flyout in sections of label and value rows) and entities (grouped by type with a count, compact rows with a type tile and an alert-count badge; entity panes in Identity, Activity, Related alerts and Logged hosts sections). Shared parts: `src/components/sentinel/XdrParts.tsx`. A bolder restructure (board queue, swimlane graph, dossier) was rejected.
- Vocabulary and look, v4 (owner, 2026-11-08, third decision: "it still strongly recalls Sentinel"). Familiar to a SOC analyst, in our own words; internal screen ids, routes and event types keep their names.
  - Menu: Workspace (Home, Query, Search), Investigate (Incidents, Hunts, Entities, Intel), Operate (Detections, Playbooks). Page titles: Workspace home, Query lab, Search, Incidents, Hunts, Entities, Intel, Detections, Playbooks. The page header is the menu group as a small caps eyebrow, the page name and the workspace as a chip (no "XDR | Incidents", no "Selected workspace", no Home > XDR breadcrumb).
  - Incident: Summary and Entities views; cards Alert timeline, Entities, Quick findings, Related incidents ("Why related": Shared entities, Same rule); toolbar Refresh, Query, Tasks, Case history; Respond > Run action; entity actions Add to Intel and Run action; left panel Workspace, Description, Sources, Linked data (Events, Alerts, Bookmarks as small cards), Updated, Created. "Incident" stays the industry term; ids read `#8758`.
  - Query lab: query tabs "Query 1" with an edited dot; "Browse saved queries"; the side pane has Data sources and Saved queries. Data sources are grouped by where the data comes from (Alerts and incidents, Endpoints, Identity, Email and collaboration, Network, Cloud, Other sources), each with an icon and its table count, each table with its row count; "Arrange: By source / A to Z" replaces the portal's Group by. Table and column names stay exact (KQL identifiers); column types show as short badges. Results: "Query complete", "n rows", "Times in UTC", a UTC badge on datetime columns, column filters that show on hover or focus.
  - Grids (incidents, results, related incidents, hunts, bookmarks, entities, intel, detection rules, playbook runs): a rounded header bar with small caps labels (results keep KQL names as they are, in mono), a chevron only on the sorted column, zebra rows, a left accent on hover and selection, a rounded violet checkbox, status pills, and the pager "Showing 1 to 4 of 4" with icon buttons. Sorting, selection, filters and keyboard access are unchanged.
  - Fonts: Manrope (interface) and IBM Plex Mono (KQL, identifiers, values), loaded with next/font in `src/app/(app)/xdr/layout.tsx` only, so the rest of the platform keeps Inter. Neutrals are cool slate instead of the portal's warm greys; the violet accent stays.
  - Home: stat cards, quick ways in, Activity over time, Needs attention (open incidents as cards, highest severity first) and Incidents by status as one segmented bar. Detections, Playbooks (device card and playbook cards), Hunts (segmented Hunt queries / Bookmarks), Entities (type filter), Intel and Search (a search card, KQL shown before it runs) follow the same cards and grid.

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
- Documentation IPs and fictional names only, as everywhere on the platform. No Microsoft logo, trademarked icon or portal look. Nothing in an XDR session names the console Microsoft Sentinel or Azure Sentinel, and the console does not use the portal's labels (Activity log, Top insights, Threat management, Configuration, a Tables tab) (tests: `src/components/sentinel/XdrNaming.render.test.ts`, `src/app/(app)/team/[id]/_components/XdrNaming.render.test.ts`, `src/app/(app)/sentinel/redirect.test.ts`).
- English UI, no em dashes.
