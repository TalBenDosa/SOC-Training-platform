# אפיון — שילוב קונסולת ה-EDR בתרחישים + סיווג-התראות תלת-דרכי

> אפיון-יישום מלא: חיבור קונסולת ה-EDR הקיימת (`/edr`) לתרחישים המוכנים, סיווג-התראות תלת-דרכי (`edr` / `hybrid` / `non_edr`) בתאימות למציאות, מניעת הצפה (Detection מול Telemetry), קורלציה מפורשת בין SIEM ל-EDR, עץ-תהליכים עם שרשראות-redirect בגלישה, ו-IOC → דו״ח. נכתב 2026-08-26.
>
> משלים את `docs/SPEC-edr-console.md` (הקונסול עצמו) ו-`docs/EDR-SIMULATION-DESIGN.md`. מבוסס-מחקר: [CyberDefenders — Alert Triage](https://cyberdefenders.org/blog/alert-triage-process/) · [Cyber Triage — Alert vs Endpoint Triage](https://www.cybertriage.com/blog/alert-triage-vs-endpoint-triage/) · [Vectra — SOC investigation workflow](https://www.vectra.ai/topics/incident-investigation) · [Microsoft Learn — RDP brute force on a host](https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/cannot-rdp-azure-vm-brute-force) · [Red Canary — Identity detection for CrowdStrike EDR](https://redcanary.com/blog/product-updates/identity-detection-support-for-crowdstrike-edr/) · MDE `DeviceNetworkEvents` / Web Threat Protection.

---

## 0. מצב קיים (ground truth מהמיפוי)

- אירוע-EDR = `TelemetryEvent` עם `source:"edr"` (רובם `event_type:"process_create"`). **אין אובייקט-detection נפרד** ואין הבחנה detection/telemetry.
- הקונסול `/edr` הוא ממשק Falcon-like מלא (עץ-תהליכים `TreeNode`, hash-lookup, RTR, Incident Workbench, containment, החלטה מדורגת) — אבל **נגיש רק מ-shift חי בדשבורד** (`edr/page.tsx:48` → `isTrainingActive()`), דרך deep-link `?case=live` שקורא `localStorage["edr_live_investigation"]`.
- `buildInvestigationFromStory` (`lib/edr/fromLiveStory.ts`) כבר בונה עץ מטלמטריית-התהליכים; מחזיר `null` לתקיפות ללא תהליך (זהות/ענן).
- מציג-התרחיש (`scenarios/[slug]/ScenarioClient.tsx` → `ScenarioLogViewer`) = **טבלת-לוג שטוחה אחת**, ללא קיבוץ-מקור, ללא הפרדת SIEM/EDR, **ללא קונסול-EDR**, ללא קורלציה.
- אין `incident_id` מתמשך על אירועים — קורלציה משוחזרת ב-render לפי host/user/ts בלבד.
- חבילות endpoint הן 60-70% EDR (bundledCryptominer 6/9) → זרם EDR-דומיננטי לא-מובחן.

---

## 1. מטרות ועקרונות

1. **EDR = יעד-חקירה** לאירוע endpoint-observable — לא עוד זרם-התראות.
2. **סיווג תלת-דרכי** לכל incident: `edr` / `hybrid` / `non_edr` — קובע אם מופיע כפתור "Investigate in EDR".
3. **בלי הצפה**: הבחנה **Detection** (1-3, alert-grade) מול **Telemetry** (process_create, pivot-only). למידה חיובית.
4. **קורלציה מפורשת**: `incident_id` משותף על כל אירועי שרשרת-תקיפה (SIEM + EDR), ניתן-לשאילתה ולדירוג.
5. **עץ-תהליכים** הורה→ילד→נכד, כולל שרשראות-redirect בגלישה.
6. **IOC → דו״ח**: מה שנאסף ב-EDR הוא מה שמצוטט בדו״ח (המדרג כבר מזכה דרך `evidenceText`).
7. **תאימות למציאות**: קריטריון ה-endpoint-observability (§3) תואם triage אמיתי.

---

## 2. מודל-נתונים (`src/lib/sim/types.ts`)

הרחבת `TelemetryEvent` (כל השדות אופציונליים — backward-compatible):

| שדה | טיפוס | על מי | תפקיד |
|---|---|---|---|
| `incident_id` | `string` | כל אירועי שרשרת-תקיפה אחת | מפתח-קורלציה מתמשך (SIEM + EDR). מדמה Sentinel "Incident" / Splunk "notable". |
| `is_detection` | `boolean` | 1-3 אירועי-EDR נבחרים | alert-grade — מוצג בזרם; שאר ה-EDR = telemetry (pivot-only). |
| `edr_scope` | `"edr" \| "hybrid" \| "non_edr"` | על אירוע ה-detection הראשי (או ברמת ה-incident) | קובע נראות כפתור-ה-EDR. |

- שדות-הקורלציה הקיימים (`hostname`, `user_email`, `src_ip`, `process.pid`/`parent_pid`, `mitre_technique`) נשארים ומשמשים לבניית-העץ; `incident_id` הוא ה-**join המפורש** מעליהם.
- **ניהול-id**: `incident_id` בפורמט `inc:<pack-slug>:<n>` — יציב, ייחודי בין-חבילתי.

---

## 3. סיווג תלת-דרכי — הכלל (`src/lib/edr/classifyScope.ts`, חדש)

**עיקרון:** endpoint-observability — האם הפעילות מותירה ארטיפקט על תחנה/שרת ספציפי.

```
signalsHost(incidentEvents):  // יש עקבה על host?
  - אירוע עם process{} (pid) על host, או
  - logon על host (event_type 4624/4625 / logon), או
  - קובץ/registry/service/scheduled-task/driver/memory על host, או
  - תופעת-לוואי/persistence על host (local-admin add, service install)

signalsControlPlane(incidentEvents):  // יש עקבה במישור-בקרה מרוחק?
  - cloud IdP sign-in (source o365/azuread/okta, ללא process), או
  - SaaS/cloud API (cloudtrail/gws), או
  - ציוד-רשת בלבד (firewall/ids/waf/proxy ללא host), או
  - email-gateway (o365 mail ללא פתיחה על host)

edr_scope =
  host && !controlPlane           → "edr"
  host && controlPlane            → "hybrid"
  !host && controlPlane           → "non_edr"
```

**מקרי-מפתח (מהמחקר):**

| Use case | scope | detection צף ב | pivot ל-EDR פותח |
|---|---|---|---|
| Maldoc / drive-by / SEO-poison / ClickFix / fake-update | `edr` | EDR detection | עץ: browser/office → payload |
| **Brute-force/spray על תחנה/שרת (RDP/SSH/SMB/local)** | `edr` | EDR/SIEM (4625) | ה-host: side-effects, local-admin, service |
| Ransomware / LSASS dump / infostealer | `edr` | EDR detection | encryptor / lsass access |
| **Kerberoasting / DCSync / PtH** | `hybrid` | SIEM/AD (4769/4662/4776) | ה-host שמריץ את הכלי |
| PsExec / WMI / WinRM lateral | `hybrid` | SIEM (4624/5145) | ה-host: `services.exe→cmd` |
| C2 beacon / DNS tunneling | `hybrid` | firewall/proxy/DNS | התהליך שמבצע beacon |
| **spray-ענן / impossible travel / OAuth / MFA-fatigue** | `non_edr` | קונסול-זהות/SIEM | — (אין host) |
| Port scan / IDS / DDoS / BEC-rule / DLP-USB | `non_edr` | NDR/firewall/O365/DLP | — |

**גלישה-ורדיירקט (Web Threat, endpoint-observable):** ה-EDR על התחנה רואה את **תהליך-הדפדפן** + DNS + חיבורים (`DeviceNetworkEvents`) → מסווג `edr` (או `hybrid` אם יש גם proxy/SWG detection). שרשרת ה-redirect (site A → 302 → adnet → CDN מזויף → payload) משוחזרת מאירועי-הרשת הקשורים ל-PID הדפדפן לפי סדר.

---

## 4. מניעת הצפה — Detection מול Telemetry

**כלל-הצגה:**
- בזרם/בטבלת-התרחיש מוצגים כשורות עליונות: **כל ה-detections** (`is_detection:true` של EDR + כל אירועי-ה-detection הלא-EDR).
- כל שאר אירועי ה-`source:"edr"` (`process_create` telemetry) **אינם שורות עליונות** — הם נחשפים **רק בתוך קונסול-ה-EDR** (עץ-התהליכים) אחרי pivot.

**annotation בכל חבילה:** על כל pack מסמנים 1-3 אירועי-EDR כ-`is_detection:true` (ההתנהגותי + הרצת-ה-payload). ברירת-מחדל: אירוע-EDR ללא `is_detection` = telemetry.

**Live feed** (`useLiveEvents.ts`): ההזרקה לזרם מסננת ל-`is_detection` (או non-EDR); הטלמטריה נשמרת לבניית-העץ אך לא מוזרקת כשורות. פותר את ה-burst של 2-3 שורות-EDR בפאזה.

**Validator** (`validate:scenarios`/`validate:feed`): כלל חדש — חבילה עם `edr_scope∈{edr,hybrid}` חייבת 1-3 detections של EDR (לא 0, לא >3); אירוע telemetry חייב `incident_id` תואם.

---

## 5. קורלציה SIEM ↔ EDR

- `incident_id` מוטבע על **כל** אירועי השרשרת (firewall/AD/O365 + EDR).
- **מציג-התרחיש**: לחיצה על detection → מדגישה את כל אירועי אותו `incident_id` בכל המקורות + מציגה **mini-timeline** כרונולוגי (reuse רעיון ה-Timeline מהקונסול).
- **בניית-העץ**: `buildInvestigationFromStory` מקבל `incidentId` ומסנן את אירועי-החבילה לאותו incident לפני בניית העץ (במקום כל ה-story).
- **דירוג**: הקורלציה ניתנת-לבדיקה — אפשר לשאול "אילו אירועים שייכים לאותו incident" ולדרג.

---

## 6. חיבור EDR ↔ תרחיש (הליבה)

**החלטת-ארכיטקטורה: פאנל-EDR מוטמע** במציג-התרחיש (לא deep-link ל-`/edr`) — נמנע מריקוד ה-`isTrainingActive()`/cross-tab-localStorage, ומחזיק את החקירה בהקשר-התרחיש.

- רכיב חדש `ScenarioEdrPanel.tsx` **עוטף את `Console`** מ-`edr/page.tsx` (מחלצים את `Console` לרכיב משותף `src/components/edr/EdrConsole.tsx` — אותו קוד, בלי ה-gate ובלי ה-routing).
- ב-`ScenarioClient.tsx`: על שורת-detection עם `edr_scope∈{edr,hybrid}` **וקיים `process{}` באותו incident** → כפתור **"Investigate in EDR"**. לחיצה בונה investigation דרך `buildInvestigationFromStory(bundle.events, incidentId)` ופותחת את הפאנל (drawer/מסך-מלא בתוך התרחיש).
- אירוע `non_edr` → **אין כפתור** (התלמיד לומד שזה נחקר ב-SIEM/זהות).
- Containment בתרחיש: משתמש באותו `containment.ts` (state מקומי לתרחיש).

**refactor נדרש:** חילוץ `Console` (edr/page.tsx:74) ל-`src/components/edr/EdrConsole.tsx` נטול-routing; `edr/page.tsx` ו-`ScenarioEdrPanel` שניהם צורכים אותו. אין שינוי התנהגות ל-`/edr` החי.

---

## 7. עץ-תהליכים + שרשראות-redirect

- העץ הקיים (`TreeNode`, ancestry הורה→ילד→נכד) נשאר — עכשיו זמין גם בתרחיש.
- **טאב Network בכל node** (כבר קיים) מורחב: לתהליכי-דפדפן מוצגת **שרשרת-ה-redirect לפי סדר** — כל שורה: `ts · method/status (302/301/JS/meta) · domain · IP · JA3` — מהאתר-התמים דרך ה-redirects ל-payload, ואז ה-node של הקובץ-שהורד כצאצא.
- **דרישת-נתונים**: חבילות web-redirect (`seoPoisonedInstaller`, `clickFixFakeCaptcha`, `fakeBrowserUpdate`, `driveByBrowserMiner`) — אירועי-הרשת שלהן צריכים לשאת את הרצף: `network.redirect_from/redirect_to` או `http.status` + סדר-timestamp, קשורים ל-`process.pid` של הדפדפן.
- `fromLiveStory.ts` — שמירת **סדר** אירועי-הרשת (היום דוחף לפי מעבר-events; לוודא סורט לפי ts) והצגת ה-status/redirect.

---

## 8. IOC → דו״ח

- פאנלי-ה-detail בקונסול כבר מציגים IOCs (hash/path/cmdline/network/signature).
- **פאנל "IOCs Collected"** חדש בקונסול: כל IOC ניתן ל-"Add to case" (hash, process, hostname, IP, domain, redirect-chain). נצבר לרשימה.
- בסיום החקירה → הרשימה **מועברת למודל-הדו״ח** (pre-fill/checklist ב-`IncidentReportModal`).
- הלולאה נסגרת: חקירה ב-EDR → איסוף IOCs → ציטוט בדו״ח → **המדרג מזכה** (התיקון הקודם: `evidenceText` מזהה כל IOC נצפה).
- **תוכן-לימוד**: חדר/שיעור "מה זה IOC" (הטקסונומיה מהשיחה: host/network/identity/email/asset + IOC מול IOA) — נלמד לפני החקירה (כלל-הברזל של soc-content-coverage-auditor).

---

## 9. קבצים שישתנו

| קובץ | שינוי |
|---|---|
| `src/lib/sim/types.ts` | `+incident_id`, `+is_detection`, `+edr_scope` על `TelemetryEvent` |
| `src/lib/edr/classifyScope.ts` (חדש) | כלל §3 — מחזיר `edr_scope` לפי אירועי-incident |
| `src/lib/sim/scenario-packs/*.ts` | annotation: `is_detection`, `edr_scope`, `incident_id` (pilot תחילה) |
| `src/components/edr/EdrConsole.tsx` (חדש) | חילוץ `Console` נטול-routing מ-`edr/page.tsx` |
| `src/app/(app)/edr/page.tsx` | צורך את `EdrConsole` (ללא שינוי התנהגות) |
| `src/components/scenarios/ScenarioEdrPanel.tsx` (חדש) | פאנל-EDR מוטמע לתרחיש |
| `src/app/(app)/scenarios/[slug]/ScenarioClient.tsx` | detection rows, כפתור "Investigate in EDR", highlight-קורלציה + mini-timeline |
| `src/lib/edr/fromLiveStory.ts` | פרמטר `incidentId` (סינון) + שמירת-סדר redirect |
| `src/app/(app)/dashboard/IncidentReportModal.tsx` | קבלת "IOCs collected" (pre-fill) |
| `scripts/validate-scenarios.mjs` / `validate-feed` | אכיפת cap-detections + `incident_id` על telemetry |
| `src/data/rooms-batch-*.ts` (חדש) | חדר "IOC fundamentals" (טקסונומיה) |

---

## 10. שלבי-יישום (phasing)

| פאזה | תוכן | תוצר-בדיקה |
|---|---|---|
| **1 — מודל** | שדות ב-`types.ts` + `classifyScope.ts` + annotation ל-**pilot 2-3 חבילות** (endpoint + hybrid + web-redirect) | tsc; classifyScope unit-test |
| **2 — de-flood** | פיצול detection/telemetry במציג-התרחיש + highlight-קורלציה + mini-timeline | חבילת-pilot מציגה 1-3 detections; טלמטריה מוסתרת |
| **3 — EDR מוטמע** | חילוץ `EdrConsole` + `ScenarioEdrPanel` + כפתור + עץ + שרשרת-redirect | pivot מתרחיש פותח עץ; `non_edr` בלי כפתור |
| **4 — IOC→דו״ח + פריסה** | פאנל IOCs → pre-fill; validators; roll ל-24 החבילות + חדר-IOC | שער-על ירוק; כל חבילה מסווגת ותקינה |

בין פאזות — **אתה בלולאה**: כל פאזה נפרסת ומאומתת לפני הבאה.

---

## 11. עיגון-ריאליזם ו-non-goals

- **ריאליזם**: detection-object + process-tree pivot = Falcon/MDE. `incident_id` = קיבוץ-Incident של SIEM לפי entity+time. web-threat via `DeviceNetworkEvents` = MDE אמיתי. הסיווג התלת-דרכי = triage אמיתי (SIEM screens → escalate-to-EDR רק כשיש endpoint).
- **Non-goals (כרגע)**: לא בונים Threat-Graph-cross-host מלא; לא grading-דשבורד-בשרת (v2); לא AI-generation לתוכן-ארגוני. פאנל-ה-EDR בתרחיש חולק את מגבלת-ה-client-grading הקיימת של הקונסול.
- **סיכון עיקרי**: annotation שגוי של detection/scope בחבילה → detection נעלם או כפתור-EDR מופיע היכן שאסור. מרוכך ע"י ה-validator (§4) + pilot לפני roll.

---

## 12. נקודות-הכרעה פתוחות (לפני יישום)

1. **pilot** — אילו 3 חבילות? הצעה: `trojanizedInstallerKeylogger` (edr), `seoPoisonedInstaller` (edr+web-redirect), חבילת-lateral (hybrid).
2. **חדר-IOC** — לבנות עכשיו (פאזה 4) או להקדים כ-prereq?
3. **פאנל מוטמע מול מסך-מלא** — drawer בתוך התרחיש, או ניווט למסך-EDR ייעודי בהקשר-התרחיש?

---

## נספח (עדכונים 2026-08-26)

### א. הפרדה מלאה בין incidents מרובים ב-EDR (דרישת-משתמש)

כשלתרחיש יש **יותר מ-incident אחד** המסווג `edr`/`hybrid` (שני `incident_id` נפרדים) — הקונסול **חייב להציגם כ-cases נפרדים לחלוטין, ללא ערבוב**:
- כל `incident_id` = **case נפרד** ב-case-switcher הקיים (ה-tabs בראש הקונסול, `edr/page.tsx:171`).
- לכל case: עץ-תהליכים, timeline, detections, Workbench score, וההחלטה — **משלו בלבד**. אף node/detection/IOC לא זולג בין incidents.
- הבנייה: `buildInvestigationFromStory(bundle.events, incidentId)` נקרא **פעם לכל `incident_id`** → `EdrInvestigation[]` נפרדים שמוזנים ל-case-switcher (בדיוק כמו `investigations[]` היום).
- מונע את הבאג-ההפוך של ההצפה: לא ערימת-עץ מבולגנת, אלא N חקירות נקיות ומופרדות.
- **ריאליזם**: תואם Falcon — כל incident הוא Workbench נפרד; אנליסט לא מערבב שני incidents באותו עץ.

### ב. תלמיד ה-IOC — הפרה-רקוויזיט כבר מסופק (אין צורך בחדר חדש)

בדיקת-כיסוי מצאה שהתוכן העיוני **כבר מלמד את כל מה שחקירת-ה-EDR דורשת** — בניית חדר-IOC חדש = כפילות. לכן פאזה 4 **אינה** בונה חדר; היא רק **מקשרת** מהפיצ׳ר לתוכן הקיים:
- `ioc-analysis` (rooms-batch-07) — סוגי-IOC, Pyramid of Pain, OSINT, pivoting, MISP, STIX/TAXII.
- rooms-batch-13-r3 — **IOC מול IOA** מפורש (דוגמת LSASS `0x1FFFFF`).
- builtinLessons — **host/process IOCs** (Win 4624/4688/4698/7045 + Sysmon 1/3/11/13: parent process, cmdline, services, scheduled tasks, registry), **redirect chains / URL shorteners / IDN homograph**, ופורמטי-התראות-EDR.
- `ioc-analysis` יושב **לפני** תוכן ה-EDR המתקדם במסלול → כלל-הברזל מקוים.

### ג. סטטוס-יישום

- **פאזה 1a הושלמה**: 3 שדות ב-`types.ts` (`incident_id`, `is_detection`, `edr_scope`); `src/lib/edr/classifyScope.ts` (הכלל התלת-דרכי) + `classifyScope.test.ts` (8 בדיקות, כולל תיקון ה-brute-force). tsc + vitest ירוקים.
- **הבא**: פאזה 1b — annotation של חבילות-pilot (`incident_id` + `is_detection` + `edr_scope`).
