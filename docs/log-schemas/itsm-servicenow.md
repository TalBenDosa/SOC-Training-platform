# ServiceNow — Table API records (incident, change_request, sc_req_item)

Category: ITSM / ticketing (context source for investigations). Vendor: ServiceNow. Native format: REST Table API JSON (JSON-native).
Platform representation: **the Table API response object exactly as returned** — `{"result": {...}}` for a single record (GET by sys_id) or `{"result": [ ... ]}` for a list.

---

## 1. Official sources

| Source | What it confirmed |
|---|---|
| https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html | `GET /api/now/table/{tableName}` and `/{sys_id}`; response wrapped in `result`; reference fields returned as `{"link": "<instance>/api/now/table/<table>/<sys_id>", "value": "<sys_id>"}`; `sysparm_display_value` = `false` (default, raw DB values) / `true` (display values) / `all` (both, as `{"display_value": ..., "value": ...}` objects); `sysparm_exclude_reference_link=true` drops `link`; `sysparm_fields`, `sysparm_query`, `sysparm_limit`. |
| ServiceNow community / docs on change states (https://www.servicenow.com/community/itsm-forum/change-management-states/m-p/2436055) | Change state model New, Assess, Authorize, Scheduled, Implement, Review, Closed, Canceled with integer values -5, -4, -3, -2, -1, 0, 3, 4. |
| ServiceNow product docs, Incident Management state model | Incident `state` 1 New, 2 In Progress, 3 On Hold, 6 Resolved, 7 Closed, 8 Canceled; `priority` 1 Critical … 5 Planning derived from `impact` × `urgency` (1 High, 2 Medium, 3 Low). |

## 2. Native format and delivery

- Pulled via REST (basic/OAuth) by SOAR/SIEM connectors, or pushed via outbound REST/Event Management. Not a log stream — records are mutable; each poll returns the current state (`sys_updated_on`, `sys_mod_count` change).
- **Default raw mode (`sysparm_display_value=false`) — the shape we standardise on:**
  - Every scalar is a **string**, even numbers and booleans (`"priority": "2"`, `"active": "true"`).
  - Choice fields carry the stored value (`"state": "-2"`, `"approval": "approved"`).
  - Date/time = `"YYYY-MM-DD HH:MM:SS"` in **UTC**, no `T`/`Z`. Empty = `""`.
  - Reference fields = `{"link": "...", "value": "<32-hex sys_id>"}`; empty reference = `""`.
- Display mode (`all`) is allowed only when a scenario explicitly shows a connector configured that way; never mix the two shapes in one record.

## 3. Core field reference

### Common (task-based tables)
| Field | Meaning | Values / notes |
|---|---|---|
| `sys_id` | Record ID | 32 lowercase hex |
| `number` | Human ID | `INC0012345`, `CHG0031877`, `RITM0010422` |
| `sys_class_name` | Table | `incident`, `change_request`, `sc_req_item` |
| `state` | State (integer as string) | see per table |
| `active` | Open/closed | `"true"` / `"false"` |
| `short_description` / `description` | Title / body | |
| `priority` / `impact` / `urgency` | 1–5 / 1–3 / 1–3 | |
| `assignment_group` / `assigned_to` | Reference -> `sys_user_group` / `sys_user` | `{link,value}` |
| `opened_by`, `opened_at` | Who/when opened | reference / UTC datetime |
| `sys_created_on`, `sys_created_by`, `sys_updated_on`, `sys_updated_by`, `sys_mod_count` | Audit columns | `sys_created_by` / `sys_updated_by` are user_name strings, not references |
| `approval` | Approval status | `not requested`, `requested`, `approved`, `rejected` |
| `work_notes`, `comments` | Journal fields | returned as `""` by the Table API (journal entries live in `sys_journal_field`) |
| `cmdb_ci` | Affected CI | reference -> `cmdb_ci` |
| `company`, `location` | References | |

### incident
`caller_id` (ref sys_user), `category` (`inquiry`, `software`, `hardware`, `network`, `database`, `security` if added by the customer — UNVERIFIED as OOB), `subcategory`, `contact_type` (`email`, `phone`, `self-service`, `walk-in`, `monitoring`), `state` (`1` New, `2` In Progress, `3` On Hold, `6` Resolved, `7` Closed, `8` Canceled), `hold_reason`, `close_code`, `close_notes`, `resolved_at`, `closed_at`, `incident_state`.

### change_request
`type` (`normal`, `standard`, `emergency`), `state` (`-5` New, `-4` Assess, `-3` Authorize, `-2` Scheduled, `-1` Implement, `0` Review, `3` Closed, `4` Canceled), `requested_by` (ref), `start_date` / `end_date` (planned window, UTC), `risk` (`1` Very High … `4` Low; exact mapping UNVERIFIED), `phase`, `justification`, `implementation_plan`, `backout_plan`, `test_plan`, `close_code` (`successful`, `successful_issues`, `unsuccessful`), `chg_model` (ref).

### sc_req_item (requested item)
`request` (ref `sc_request`), `cat_item` (ref `sc_cat_item`), `requested_for` (ref sys_user), `opened_by`, `quantity`, `stage` (`waiting_for_approval`, `request_approved`, `fulfillment`, `complete`, `Request Cancelled`), `state` (`-5` Pending, `1` Open, `2` Work in Progress, `3` Closed Complete, `4` Closed Incomplete, `7` Closed Skipped), `approval`, `due_date`.

## 4. Realistic samples (raw mode, trimmed to the investigation-relevant columns — a real response returns ~80–100 columns)

### 4.1 Approved, scheduled normal change (justifies an admin login at night)
```json
{"result": {
  "sys_id": "4e1c8a2bdb7f1910a3c5f0e1ca9619d4",
  "number": "CHG0031877",
  "sys_class_name": "change_request",
  "type": "normal",
  "state": "-2",
  "phase": "requested",
  "approval": "approved",
  "active": "true",
  "priority": "3",
  "impact": "2",
  "urgency": "3",
  "risk": "3",
  "short_description": "Rebuild indexes on billing production DB (PRD-SQL-03)",
  "description": "Quarterly maintenance. Index rebuild and statistics update on BillingDB. DBA will connect via Cloudflare Access to prod-db-admin.",
  "justification": "Query latency on invoice reports exceeded SLA.",
  "implementation_plan": "1. Snapshot DB 2. Run maintenance job 3. Validate report runtimes",
  "backout_plan": "Restore from pre-change snapshot.",
  "requested_by": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user/a51c7e038d925f46b0a32e9d6f1c8b74", "value": "a51c7e038d925f46b0a32e9d6f1c8b74"},
  "assignment_group": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user_group/9f0e2d4bdb3b1910a3c5f0e1ca96192a", "value": "9f0e2d4bdb3b1910a3c5f0e1ca96192a"},
  "assigned_to": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user/a51c7e038d925f46b0a32e9d6f1c8b74", "value": "a51c7e038d925f46b0a32e9d6f1c8b74"},
  "cmdb_ci": {"link": "https://nexacorp.service-now.com/api/now/table/cmdb_ci/1b7d3f60db7b1910a3c5f0e1ca96195e", "value": "1b7d3f60db7b1910a3c5f0e1ca96195e"},
  "start_date": "2026-10-01 07:00:00",
  "end_date": "2026-10-01 09:00:00",
  "opened_by": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user/a51c7e038d925f46b0a32e9d6f1c8b74", "value": "a51c7e038d925f46b0a32e9d6f1c8b74"},
  "opened_at": "2026-09-28 12:14:09",
  "sys_created_on": "2026-09-28 12:14:09",
  "sys_created_by": "oren.katz",
  "sys_updated_on": "2026-09-30 15:42:51",
  "sys_updated_by": "it.cab.chair",
  "sys_mod_count": "9",
  "close_code": "",
  "work_notes": "",
  "comments": ""
}}
```

### 4.2 Same change with `sysparm_display_value=all` (only if the connector is configured so)
```json
{"result": {
  "number": {"display_value": "CHG0031877", "value": "CHG0031877"},
  "state": {"display_value": "Scheduled", "value": "-2"},
  "approval": {"display_value": "Approved", "value": "approved"},
  "type": {"display_value": "Normal", "value": "normal"},
  "assigned_to": {"display_value": "Oren Katz", "link": "https://nexacorp.service-now.com/api/now/table/sys_user/a51c7e038d925f46b0a32e9d6f1c8b74", "value": "a51c7e038d925f46b0a32e9d6f1c8b74"},
  "start_date": {"display_value": "01/10/2026 10:00:00", "value": "2026-10-01 07:00:00"},
  "end_date": {"display_value": "01/10/2026 12:00:00", "value": "2026-10-01 09:00:00"}
}}
```
(`display_value` dates follow the API user's timezone/format — here Asia/Jerusalem, dd/MM/yyyy.)

### 4.3 Security incident opened by the SOC (VPN account compromise suspicion)
```json
{"result": {
  "sys_id": "c2a9f7e1db3f1910a3c5f0e1ca9619b7",
  "number": "INC0048213",
  "sys_class_name": "incident",
  "state": "2",
  "incident_state": "2",
  "active": "true",
  "impact": "2",
  "urgency": "1",
  "priority": "2",
  "category": "network",
  "subcategory": "vpn",
  "contact_type": "monitoring",
  "short_description": "Concurrent VPN sessions for dana.levi from IL and DE",
  "description": "GlobalProtect gateway-connected for dana.levi@nexacorp.co.il from 198.51.100.203 (DE, VM serial) at 09:17 IDT while IL session from 203.0.113.24 active since 08:02. User contacted by phone: denies DE login. Session terminated, password reset requested.",
  "caller_id": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user/0b6e2f9a7c415d38a1e294f3c6b8d071", "value": "0b6e2f9a7c415d38a1e294f3c6b8d071"},
  "assignment_group": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user_group/3d6f1a27db7f1910a3c5f0e1ca961903", "value": "3d6f1a27db7f1910a3c5f0e1ca961903"},
  "assigned_to": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user/77e0c41bdb3b1910a3c5f0e1ca9619aa", "value": "77e0c41bdb3b1910a3c5f0e1ca9619aa"},
  "cmdb_ci": "",
  "opened_by": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user/77e0c41bdb3b1910a3c5f0e1ca9619aa", "value": "77e0c41bdb3b1910a3c5f0e1ca9619aa"},
  "opened_at": "2026-10-01 06:24:10",
  "sys_created_on": "2026-10-01 06:24:10",
  "sys_created_by": "soc.t1.noa",
  "sys_updated_on": "2026-10-01 06:51:37",
  "sys_updated_by": "soc.t2.amir",
  "sys_mod_count": "4",
  "hold_reason": "",
  "resolved_at": "",
  "closed_at": "",
  "close_code": "",
  "close_notes": "",
  "work_notes": "",
  "comments": ""
}}
```

### 4.4 Resolved incident (false positive — sanctioned travel)
```json
{"result": {
  "sys_id": "e81b04c5db7f1910a3c5f0e1ca9619e2",
  "number": "INC0048197",
  "sys_class_name": "incident",
  "state": "6",
  "incident_state": "6",
  "active": "true",
  "impact": "3",
  "urgency": "3",
  "priority": "5",
  "category": "network",
  "subcategory": "vpn",
  "contact_type": "monitoring",
  "short_description": "VPN login from NL for r.mizrahi",
  "caller_id": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user/3e8b1d479a065c2fb7d36f0e2a9c4b18", "value": "3e8b1d479a065c2fb7d36f0e2a9c4b18"},
  "assignment_group": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user_group/3d6f1a27db7f1910a3c5f0e1ca961903", "value": "3d6f1a27db7f1910a3c5f0e1ca961903"},
  "opened_at": "2026-09-30 01:02:44",
  "resolved_at": "2026-09-30 07:15:20",
  "close_code": "Solved (Permanently)",
  "close_notes": "Travel approved in RITM0010422 (Amsterdam trade show 29/09-03/10). Corporate laptop confirmed.",
  "sys_updated_on": "2026-09-30 07:15:20",
  "sys_updated_by": "soc.t1.noa",
  "sys_mod_count": "3"
}}
```
(`close_code` choice values differ by release/customisation; `Solved (Permanently)` is a common OOB value, UNVERIFIED for the latest release.)

### 4.5 Requested item — temporary admin access request (approved)
```json
{"result": {
  "sys_id": "5a7e93d0db3f1910a3c5f0e1ca961977",
  "number": "RITM0010588",
  "sys_class_name": "sc_req_item",
  "request": {"link": "https://nexacorp.service-now.com/api/now/table/sc_request/1c4f82d0db3f1910a3c5f0e1ca961971", "value": "1c4f82d0db3f1910a3c5f0e1ca961971"},
  "cat_item": {"link": "https://nexacorp.service-now.com/api/now/table/sc_cat_item/8b2d6e14db7b1910a3c5f0e1ca9619c0", "value": "8b2d6e14db7b1910a3c5f0e1ca9619c0"},
  "requested_for": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user/a51c7e038d925f46b0a32e9d6f1c8b74", "value": "a51c7e038d925f46b0a32e9d6f1c8b74"},
  "opened_by": {"link": "https://nexacorp.service-now.com/api/now/table/sys_user/a51c7e038d925f46b0a32e9d6f1c8b74", "value": "a51c7e038d925f46b0a32e9d6f1c8b74"},
  "short_description": "Temporary local admin on NXC-WS-1188 (48h)",
  "quantity": "1",
  "approval": "approved",
  "stage": "fulfillment",
  "state": "2",
  "active": "true",
  "due_date": "2026-10-03 07:00:00",
  "opened_at": "2026-09-30 13:05:31",
  "sys_created_on": "2026-09-30 13:05:31",
  "sys_created_by": "oren.katz",
  "sys_updated_on": "2026-09-30 16:20:02",
  "sys_updated_by": "system",
  "sys_mod_count": "6"
}}
```

## 5. Investigation notes

- **Is this activity sanctioned?** Match the user/host/time of an alert to an open `change_request` (`state` -2/-1, `approval=approved`, `start_date` <= event time <= `end_date`, matching `cmdb_ci` / `assigned_to`) or an approved `sc_req_item` (access, travel). Remember the window is UTC.
- Resolve references by following `link` (or `value` against `sys_user` -> `user_name`, `email`). The `value` sys_id never equals an AD SID or email.
- Red flags: change created/approved minutes before the activity, `sys_created_by` = the same person who approved, `type=emergency` with no incident, `sys_mod_count` jump on an old closed record, `start_date` edited after the fact (`sys_updated_on` after the event).
- Incident `number` is the case reference written into the SOC report and in Cloudflare Access `PurposeJustificationResponse` / change tickets.

## 6. Common mistakes / fields that do NOT exist

- No top-level array or object without `result`; no `records`, `data`, `items` wrappers.
- Raw mode values are strings: `"state": "2"`, not `2`; `"active": "true"`, not `true`.
- References are objects `{link, value}` — not bare names like `"assigned_to": "Oren Katz"` (that appears only as `display_value` in display mode).
- Datetimes are `YYYY-MM-DD HH:MM:SS` UTC — not ISO with `T`/`Z`, not epoch.
- Incident has `caller_id`; change has `requested_by`; requested item has `requested_for` — don't swap them. `requested_for` on incident does not exist OOB.
- `work_notes`/`comments` come back empty from the Table API; journal text lives in `sys_journal_field`.
- `sys_created_by` / `sys_updated_by` are plain user_name strings, not references.
- No `severity` on incident OOB in the SOC sense (the OOB `severity` field exists but is rarely used; prioritisation is `priority`).
