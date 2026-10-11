# אפיון UX/UI — Team-SOC · מסך-לכל-תפקיד לבנייה-מחדש (definitive per-role screen spec)

> **מטרה במשפט אחד:** להגדיר, לכל אחד משמונת התפקידים בחדר-האירוע, את **המסך המלוטש** שאליו בונים — מה רואים, איך מנטרים, איך אוספים אינדיקטורים, איך מוסרים דו"ח/hand-off, מצבי-הריק/טעינה/שגיאה, ואיך נמדדת ההצלחה — עם **gap-analysis** של הבילד הנוכחי מול היעד.
> **תאריך:** 2026-09-14
> **סטטוס:** אפיון UX/UI בלבד — אין שינויי-קוד. זו **שכבת-ה-UX/UI מעל** `SPEC-team-soc-multiplayer.md`, מעוגנת ב-**בילד הקיים** (`src/app/(app)/team/[id]/page.tsx`, `EventFeed.tsx`, מיגרציות `0049–0056`).
> **למה המסמך הזה קיים:** התחזוקן מרגיש שה-UX של חדר-הצוות "מחוספס / לא חלק". המסמך הזה הוא ה-blueprint לבנייה-מחדש: קונקרטי, דעתני, ובר-מימוש — מפתח יכול לבנות כל מסך ממנו.
> **מוסכמות:** עברית להסבר; **אנגלית/verbatim** לכל role-ID, event-type, שם-שדה, שם-קומפוננטה ולייבל-כפתור. תגיות בשלות: **✅ built** (רץ היום) · **🔧 needs-work** (קיים אך מחוספס/חלקי) · **🔜 later** (מוגדר במאסטר, טרם נבנה). RTL-friendly.
> **מקורות-הצלבה (לא סותרים):** `SPEC-team-soc-multiplayer.md` (מאסטר — §3 תפקידים, §6 ניקוד, §13 דרישות-טל + לובי-מגובב) · `SPEC-team-roles-playbook.md` (ספר-תפקידים) · `SPEC-edr-console.md` · `REALISM-roadmap.md` · `nice-framework-mapping.md`.

---

## 1. עקרונות-עיצוב (Design principles)

שמונה עקרונות שכל מסך במסמך נגזר מהם. כל אחד מנוסח כ**חוק-הכרעה** — כשיש התנגשות, זה מה שמכריע.

1. **role-focus — כל מסך מראה רק את מה שהתפקיד צריך.** תפקיד = הגבלה, לא רק תצוגה (מאסטר §1.4.1). הפאנל-הימני מציג פעולה **אחת** דומיננטית; כל השאר משני. היום T3 מקבל ערימה של `T2Console + HuntConsole + TeamIntel + ActivityLog` — זו הפרת-העיקרון (🔧).
2. **הפיד הוא האמת המשותפת.** ה-`EventFeed` בשמאל זהה לכולם — אותו לוג באותה שנייה (Broadcast-from-DB). כל התפקידים מדברים על **אותו** אירוע. הפיד לעולם לא נדחק מתחת ל-fold ע"י פאנל אחר.
3. **פעולה-ראשית אחת לכל תפקיד.** T1=Escalate · T2=Request-containment · T3=Confirm-scope · Lead=Approve · DE=Publish-rule · TI=Publish-intel · Mgr=Post-handover. הכפתור הזה הוא ה-CTA היחיד בצבע-primary בפאנל.
4. **"waiting for you" clarity.** לכל תפקיד צריך להיות ברור, במבט-חטף, **מה מחכה לו עכשיו** — תור-נכנס עם מונה (`Escalations for you (3)`), ומה **הוא** משאיר לאחרים לחכות לו.
5. **no answer leakage.** אפס hints ב-raw; ה-`RuleLevelBadge` ניטרלי-צבע בכוונה; MITRE נחשף רק בהרחבת-שורה; `expected_verdict`/answer-key לעולם לא בלקוח לפני `ended`. זה כבר נאכף ב-`EventFeed`; חדר-הצוות חייב לשמר זאת.
6. **calm under load.** ~3,000 התראות/יום, 46% FP (מאסטר §1.1). המסך חייב להישאר קריא כשהפיד זורם — צבע רק על מה שמצריך פעולה, שאר הפיד אפור. אין ניקוד-חי (מעודד score-gaming).
7. **always-know-what-to-do.** באנר-directive לפי-תפקיד גלוי-תמיד (✅ קיים: `roleDirective`), + first-use `RoleGuideModal`. מתאמן לעולם לא תקוע ב"מה עכשיו".
8. **consistency with the single-player dashboard.** אותו `EventFeed`, אותו `DetailPanel`, אותו `ThreatIntelDrawer`, אותה מתודולוגיית `SocMethodologyBanner` (Source→Actors→Behavior→Pattern→Classify). מי שלמד לבד — מזהה הכל.
9. **accessibility / RTL.** עברית-הסבר; כל אינטראקטיב עם `focus-visible`; שורות-פיד נגישות-מקלדת (Enter/Space כבר עובד); tab-order הגיוני; ניגודיות תואמת-theme.
10. **latency-forgiving.** optimistic apply → reconcile על event סמכותי; מצב-ניתוק ברור ("מתחבר מחדש…"); ה-DB reconcile safety-net (poll כל 6s) כבר קיים כך שאף לוג לא הולך לאיבוד.

---

## 2. השלד המשותף (The shared shell)

המסגרת שכל מסך-תפקיד יושב בתוכה בפאזת **RUNNING**. מעוגן ב-`team/[id]/page.tsx` (בלוק `phase === "running"`).

### 2.1 רכיבי-הכרום (chrome)

| רכיב | מה מציג | מקור בקוד | בשלות |
|---|---|---|---|
| **Topbar** | כותרת "Live team exercise" + subtitle `company_id · difficulty` | `<Topbar>` | ✅ |
| **top status strip** | `● Radio Live` · `N online · K logs · you: <role>` · `? Guide` · `End exercise` (staff) | שורת ה-`text-neon-green` | ✅ |
| **role badge** | תג-role בצבע-cyber (`ROLE_LABEL[role]`) | בתוך ה-directive banner | ✅ |
| **directive banner** | "מה לעשות עכשיו" לפי-תפקיד + "how my role works →" | `roleDirective()` | ✅ |
| **Shared Case** | status stepper · owner · scope · evidence · notes | `<SharedCase>` | ✅ 🔧 (היררכיה — ראה §10) |
| **running layout grid** | `grid lg:grid-cols-[1fr_380px]` — feed שמאל / console ימין | ה-`<div className="grid …">` | ✅ 🔧 |
| **theme tokens** | `bg` · `bg-elevated` · `bg-hover` · `border` · `cyber-500/300` · `neon-green/amber/blue/purple` · `severity-high/critical/medium` · `slate-*` | Tailwind config | ✅ |
| **first-use guide** | `RoleGuideModal` פעם-אחת/role (`localStorage team-guide-seen-<role>`) | `<RoleGuideModal>` | ✅ |
| **bottom bar (SLA timers · cadence · nudge)** | טיימרי-SLA לאירועי high/crit · cadence-timer ל-Lead · nudge | מאסטר §7.2 | 🔜 later |

### 2.2 ה-wireframe של השלד

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Topbar:  Live team exercise            NexaCorp · easy                          │
├──────────────────────────────────────────────────────────────────────────────┤
│ ● Live — same feed for the whole team      6 online · 84 logs · you: Tier-1  [? Guide] [End] │
├──────────────────────────────────────────────────────────────────────────────┤
│ [T1] Triage the feed — set a disposition on each log, escalate real ones.  how my role works →│  ← directive banner
├──────────────────────────────────────────────────────────────────────────────┤
│ 📁 Shared case   [investigating]  [sev high]                    owner: Rani     │  ← Shared Case (full-width)
│   new › triaged › investigating › contained › eradicated › closed              │
│   Hosts: FIN-WS-07   Users: jdoe@…   Techniques: T1059.001  |  Evidence (3)     │
├────────────────────────────────────────────────┬─────────────────────────────┤
│ LEFT  (grid 1fr)                                │ RIGHT (grid 380px)          │
│ ┌────────────────────────────────────────────┐ │ ┌─────────────────────────┐ │
│ │ EventFeed  (the SAME single-player feed)    │ │ │  <ROLE CONSOLE>         │ │
│ │  Time range: 15m 1h 4h [All]      84 events │ │ │   role-gated primary    │ │
│ │  ▸ 14:02:11  FIN-WS-07  [EDR]  putty.exe …  │ │ │   action panel          │ │
│ │  ▾ 14:03:40  FIN-WS-07  [EDR]  powershell…  │ │ ├─────────────────────────┤ │
│ │     Analysis | Raw log   MITRE T1059.001    │ │ │  Team intel (shared)    │ │
│ │     Check Hash · IP · Domain (ThreatIntel)  │ │ ├─────────────────────────┤ │
│ └────────────────────────────────────────────┘ │ │  Team activity (log)    │ │
│                                                 │ └─────────────────────────┘ │
└────────────────────────────────────────────────┴─────────────────────────────┘
```

> **הערת-היררכיה (🔧):** בבילד היום ה-Shared Case הוא full-width **מעל** ה-grid, מה שדוחף את ה-feed מטה ומתחרה על תשומת-הלב עם האמת-המשותפת (עקרון 2). היעד: Shared Case דק וניתן-לקיפול (collapsible summary bar) כברירת-מחדל, נפתח לפירוט בלחיצה — ראה §10 שורה G-02.

---

## 3. Tier-1 Triage (`t1`) — ✅ built (`T1Console`)

**המשימה:** לשמור על התור נקי — לזהות מה אמיתי, לסגור FP עם נימוק, להסלים מה שחוצה-סף, מהר ובדיוק.

### 3.a מה רואה על המסך (screen)

```
RIGHT PANEL — Tier-1 triage                              (role-gated)
┌────────────────────────────────────────────────┐
│ 🛡 Tier-1 triage                                │
│ Pick a log ▼ [ #142 Encoded PowerShell · —    ] │  ← <select> על כל feed.event (🔧 רשימה שטוחה)
│ [ true positive ] [ false positive ] [ benign ] │  ← disposition.set {event_id, verdict}
│ ─────────────────────────────────────────────── │
│ ESCALATE TO TIER-2                               │
│ What did you see? (one line) __________________  │  ← form.what   (חובה)
│ Why suspicious? name indicator/technique         │  ← form.why    (בקוד ≥10 תווים;
│  _____________________________________________   │     §5.2 דורש ≥20 מילים 🔜)
│ [ impact: host ▼ ]        [ conf: med ▼ ]        │  ← impact enum · confidence 0.5/0.7/0.9
│ [ ↗ Escalate ]                                   │  ← escalation.requested  (primary CTA)
└────────────────────────────────────────────────┘
     shared: EventFeed (left) · Shared Case · Team intel · Team activity
```

- **role-gated:** T1 **לא** רואה isolate/kill/block/approve. יש לו רק disposition + escalate. תואם מטריצת §3.7.
- **shared:** הפיד, ה-Shared Case, `TeamIntel`, `ActivityLog`.
- **היעד המלוטש (🔧/🔜):** להחליף את ה-`<select>` השטוח ב**תור-triage ממוין לפי `ruleLevel`/severity** עם סימון "כבר-נתן-disposition"; לחיצה על שורת-פיד → בחירה-אוטומטית של אותו לוג בקונסולה (click-to-select, במקום dropdown ידני); באדג'-SLA לאירועי high/crit; ערוץ help-desk (`ticket.answered`).

### 3.b איך מנטר (monitor)

T1 מנטר את **הפיד** דרך העיניים של `SocMethodologyBanner`: Source→Actors→Behavior→Pattern→Classify. על ה-**PuTTY-trojan chain** (מייל-פישינג → `putty.exe` טרוג'ני מ-`Downloads` → beacon C2 → encoded PowerShell → Kerberoasting → exfil ל-mega.nz):

1. אירוע high נכנס: `▸ 14:02  FIN-WS-07  [EDR]  putty.exe spawned by WINWORD.EXE  [level 8]`.
2. T1 מסנן רעש: משתמש ב-**Time range** (15m) של ה-`EventFeed` להתמקד בפעילות-האחרונה, ומדלג על שורות level 1–3 (routine).
3. "waiting for you" ל-T1 = **הפיד עצמו** — כל שורה שלא קיבלה disposition היא משימה פתוחה. (🔜 היעד: תור-triage שמראה כמה נותרו).

### 3.c איך אוסף אינדיקטורים (collect indicators)

הצעדים הקונקרטיים על ה-UI הקיים:
1. לוחץ על שורת-הפיד → מרחיב את ה-`DetailPanel` → פולט `event.opened` (🔧 היום ה-payload ריק — ללא `event_id`/`dwell_ms`).
2. עובר ל-**Raw log** tab → קורא את הבייטים: `process.parent_name=WINWORD.EXE`, `process.path=…\Downloads\putty.exe`, `signed=false`, `process.cmdline` עם `-enc`. שלושת ה-red-flags.
3. מרחיב `MITRE ATT&CK` → קורא "What to look for in logs".
4. אם יש hash/IP/domain — לוחץ **Check Hash · Threat Intel** → `ThreatIntelDrawer` (VT/IP/domain lookup). T1 **לא** נכנס ל-EDR (`/edr`) — קרקע של T2/T3.
5. מסמן disposition = **true positive**.

- **סט-אינדיקטורים טוב:** parent אנומלי + path אנומלי + unsigned + `-enc` + hash-verdict → מנגנון שלם.
- **סט-אינדיקטורים חלש:** "נראה חשוד" בלי לפתוח raw (dwell נמוך), ללא הצלבה.

### 3.d איך מעביר דו"ח / hand-off (report)

**הפעולה:** `escalation.requested` — הטופס המדויק (payload בקוד):

| שדה | לייבל ב-UI | ולידציה בקוד | §5.2 (יעד) |
|---|---|---|---|
| `event_id` | Pick a log ▼ | חובה (select) | evidence_ids[] ≥1 🔜 |
| `what` | What did you see? | non-empty | ✅ |
| `why` | Why suspicious? | `.length ≥ 10` | ≥20 מילים 🔜 |
| `impact` | impact: host/user/segment/org | enum | ✅ |
| `confidence` | conf: low/med/high → 0.5/0.7/0.9 | ✅ | קליברציה 🔜 |
| `requested_action` | — | לא נלכד | investigate 🔜 |

**מי מקבל:** T2/T3 — נוחת ב-`T2Console` "Escalations for you (N)". **hand-off שלם** = מנגנון ב-`why` (parent/path/technique) + impact + confidence מכויל, לא "ליתר-ביטחון".

**מבחני-אימות (🔧):** ה-CTA disabled עד ש-`what` מלא ו-`why≥10` — טוב. חסר: אכיפת-מנגנון ב-`why`, ריבוי-ראיות.

### 3.e מצבים (states)

| מצב | copy / התנהגות |
|---|---|
| empty (פיד ריק) | "Press Start — the shift feed will stream here." (מגיע מ-`EventFeed` fallback) |
| loading | `Loader2` spinner + "Loading…" |
| first-action | `RoleGuideModal` פעם-אחת + directive banner |
| error | באדג'-שגיאה אדום (`setError`) "action_not_allowed / seq_conflict" |
| nothing waiting | (🔜) "Queue clear — nice. Watch the feed for the next alert." |

### 3.f מדדי-הצלחה (success metrics) — כרטיס T1

> **החלטת-סולם:** מסמך זה משתמש ב-**0/4/8/12** (4 עמודות, קריאוּת) — תואם ל-playbook. המאסטר §6.3 משתמש ב-**0/4/6/8/12** (5 עמודות, Locked Shields). **ההמלצה:** לאחד ל-0/4/8/12 לפני בניית מסך-הרובריקה (ראה §11 שאלה 2).

| # | קריטריון | 12 (excellent) | 8 | 4 | 0 (weak) | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | disposition accuracy | ≥90% מול ground-truth | 75–89% | 50–74% | <50% | `disposition.set.verdict` vs `expected_verdict` |
| 2 | escalation precision | ≥80% אושרו + 0 אבודות | 60–79% | 40–59% / אבודה | <40% | `escalation.requested`→(`.acknowledged`) |
| 3 | card completeness | כל השדות + מנגנון ב-`why` + conf | חסר שדה | רק "נראה חשוד" | ריק | payload של `escalation.requested` (=`escQualityScore`) |
| 4 | time-to-triage (high/crit) | ≤5′ | ≤10′ | ≤15′ | >15′ | Δ(`feed.event`→`disposition.set`) |
| 5 | help-desk tickets (🔜) | כולם בזמן + vishing נדחה | איחור אחד | אישר vishing | התעלם | `ticket.answered` |

- **excellent:** "escalate signals, not doubts" — כרטיס עם מנגנון + confidence מכויל; FP נסגר עם הסבר.
- **weak:** closure 95%+ (מסלים-חסר) או escalation >30% (מפחד); כרטיסים ריקים.
- **NICE:** PR-CDA-001 (T0020, T0023, T0155, T0164).

---

## 4. Tier-2 Investigator (`t2`) — ✅ built (`T2Console`, משותף עם t3)

**המשימה:** לקבל הסלמות, לחקור לעומק, לבנות scope, ולבקש הכלה.

### 4.a מה רואה על המסך (screen)

```
RIGHT PANEL — Tier-2 investigator                        (role-gated)
┌────────────────────────────────────────────────┐
│ 🚨 Escalations for you (3)                       │  ← "waiting for you" inbox
│ ┌────────────────────────────────────────────┐  │
│ │ Trojanized PuTTY on FIN-WS-07…             │  │  ← what
│ │ parent WINWORD, unsigned, encoded PS       │  │  ← why
│ │ from Dana · impact host · conf 0.9         │  │  ← actor · impact · confidence
│ │ [ ✓ Acknowledge ]                          │  │  ← escalation.acknowledged
│ │ (after ack) [ 🛡 Request containment ]     │  │  ← containment.requested (primary CTA)
│ └────────────────────────────────────────────┘  │
└────────────────────────────────────────────────┘
   🔜 target: [ Investigate in EDR ] · timeline builder · pivot-to-filter · scope.set · report
```

- **role-gated:** T2 יכול `containment.requested` (מבקש, לא מבצע); אחרי אישור Lead — isolate/kill ב-EDR. לא מאשר containment בעצמו, לא כותב rule.
- **מה קיים היום (✅):** ack + request-containment.
- **מה חסר (🔧/🔜, מ-§3.2 של המאסטר):** כפתור **"Investigate in EDR"** (פותח `/edr` על ה-host טעון-בעץ-התהליכים — `SPEC-edr-console.md`); בונה-ציר-זמן; חיפוש/pivot בפיד (ה-`EventFeed` בחדר-הצוות **לא** חושף את בקרות ה-severity/source/search — hardcoded `"all"`); עדכון סטטוס-תיק (קיים ב-`SharedCase`); כותב-דוח (`/api/dashboard/incident-report`); `scope.set`.

### 4.b איך מנטר (monitor)

ה-inbox `Escalations for you (N)` הוא ה-monitor הראשי — כל כרטיס = משימה. ה-`ActivityLog` בימין מראה מה שאר הצוות עושה (למניעת עבודה-כפולה). על ה-PuTTY-chain: T2 רואה את הסלמת-T1, מאשר תוך דקות (ה-SLA-clock מ-§5.2 מתחיל ב-`escalation.requested`). מנטר גם את ה-Shared Case scope שמתמלא-מעצמו מההסלמות.

### 4.c איך אוסף אינדיקטורים (collect indicators)

1. **Acknowledge** → `escalation.acknowledged {event_id}` (T1 רואה ב-`ActivityLog`).
2. 🔜 **Investigate in EDR** → `/edr` על FIN-WS-07: `WINWORD.EXE → putty.exe(unsigned) → powershell.exe(-enc) → cmd`. קורא node-אחר-node: cmdline, path, signer, SHA256 → hash lookup → verdict זדוני.
3. 🔜 **pivot** על ה-hash/IP בפיד → מוצא beacon מ-host שני + `4769 RC4 burst` (Kerberoasting) → scope = {hosts:2, users:1, techniques:[T1566, T1059.001, T1558.003]}.
4. מצמיד ראיות: היום הראיות ב-Shared Case = ההסלמות עצמן (auto); היעד (🔜) `evidence.pinned` מפורש מכל שורת-פיד.
5. **Request containment** עם נימוק-impact.

- **טוב:** ציר-זמן **לפני** בקשת-הכלה; scope מלא; hash-verdict מוצלב.
- **חלש:** reimage רפלקסיבי; ציר-זמן רק מה-EDR בלי הפיד.

### 4.d איך מעביר דו"ח / hand-off (report)

**הפעולה:** `containment.requested {event_id, target, reason}` → **Lead** (נוחת ב-`LeadConsole` "Containment approvals (N)"). היום `target`/`reason` נגזרים אוטומטית מההסלמה (`target: p.impact, reason: p.what`) — 🔧 היעד: שדות מפורשים (target-host מדויק + reason-impact נפרד). **hand-off שלם** = case עם timeline + scope + evidence + recommended containment; ה-Lead צריך רק "לאשר או לא".

**הזרימה המלאה T1→T2→T3→Lead→(Mgr/external), מצוירת פעם-אחת:**

```mermaid
sequenceDiagram
    autonumber
    participant F as Live Feed (server · pg_cron)
    participant T1 as T1 Triage
    participant T2 as T2 Investigator
    participant T3 as T3 / Hunter
    participant L as Incident Lead
    participant DE as Detection Eng
    participant TI as Threat Intel
    participant M as SOC Manager
    F->>T1: feed.event (high) — putty.exe by WINWORD on FIN-WS-07
    T1->>T1: event.opened → disposition.set (true_positive)
    T1->>T2: escalation.requested {what, why=mechanism, impact, confidence}
    T2->>T1: escalation.acknowledged (SLA clock stops)
    T2->>T2: (🔜 edr.opened) → scope building on Shared Case
    T2->>T3: escalation.requested {to_role:t3} — deep hunt (🔜 to_role)
    T3->>T3: hunt.logged (2nd persistence) → (🔜 scope.confirmed)
    T3->>TI: request attribution (🔜)
    TI->>L: intel.published {actor, technique, confidence, next_expected}
    T2->>L: containment.requested {target, reason}
    L->>L: (🔜 decision.logged) approve; reason: C2 active, not prod
    L->>T2: containment.approved
    T2->>F: (🔜 containment.executed) → beacon stops (shared state)
    T3->>DE: request rule for exposed technique (🔜)
    DE->>F: rule.published (back-tested, matched N)
    L->>M: (🔜 sitrep.sent / handover.noted to next shift)
    M->>M: handover.noted (workload + open cases)
```

### 4.e מצבים (states)

| מצב | copy |
|---|---|
| nothing waiting | "Nothing escalated yet. Tier-1 sends cases here." (✅ בקוד) |
| loading | inline `busy` על כל כרטיס |
| acked | "✓ acknowledged" (ירוק) — ואז נפתח כפתור Request containment |
| error | `action_not_allowed` אם ה-role/phase לא תואם |

### 4.f מדדי-הצלחה — כרטיס T2 (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | ack-latency | ≤2′ | ≤5′ | ≤10′ | >SLA/אבוד | Δ(`escalation.requested`→`.acknowledged`) |
| 2 | timeline accuracy | כל שלבי ה-chain בסדר | חוסר שלב | סדר שגוי | לא נבנה | `case`/`note` timeline (🔜) vs ground-truth |
| 3 | scoping completeness | כל hosts/users/tech | ≥70% | 40–69% | <40% | `scope.set` (🔜) / Shared-Case scope vs answer-key |
| 4 | containment recommendation | נכונה+מנומקת+בזמן | נימוק חלש | מאוחרת | host תמים | `containment.requested.reason` + target-correctness |
| 5 | incident report | grader ≥80 | 60–79 | 40–59 | <40/לא הוגש | `report.graded.score` (🔜) |

- **excellent:** ack מהיר · scope מלא · בקשה עם נימוק-impact · פידבק ל-T1.
- **weak:** isolate רפלקסיבי · שכח ack (T1 "תלוי באוויר") · מפקיע את ה-Lead.
- **NICE:** PR-CIR-001 (T0041, T0047, T0161, T0163, T0175).

---

## 5. Tier-3 / Threat Hunter (`t3`) — ✅ built (`T2Console` + `HuntConsole`)

**המשימה:** חקירת-עומק + ציד hypothesis-driven — מעבר לתור. קובע scope סופי, מנחה את T2.

> **מצב בקוד:** `t3` מרנדר את **`T2Console`** (משותף עם t2) **פלוס** `HuntConsole` ייעודי. אין עדיין scope-review/confirm ייעודי (🔜).

### 5.a מה רואה על המסך (screen)

```
RIGHT PANEL — Tier-3 / Threat Hunter
┌────────────────────────────────────────────────┐
│ 🚨 Escalations for you (2)   (shared T2Console)  │  ← ack + request-containment
│  … same inbox as T2 …                            │
├────────────────────────────────────────────────┤
│ 🛡 Threat hunt (Tier-3)          (HuntConsole ✅) │
│ Hypothesis: "putty C2 has a second beacon" ____  │  ← f.hypothesis (≥8 תווים)
│ Finding / evidence: ___________________________  │  ← f.finding
│ MITRE technique (optional): T1021.002 __________  │  ← f.technique
│ [ Log hunt finding ]                             │  ← hunt.logged (primary CTA)
└────────────────────────────────────────────────┘
   🔜 target: full EDR · scope review [Confirm / Amend & return] · pivot-to-filter
```

- **role-gated:** T3 מקבל את **קונסולת-ה-EDR המלאה** (🔜), pivot חופשי על כל הפיד, ו-hunt-board. מאשר/דוחה scope של T2. isolate/kill רק אחרי אישור Lead.
- **ההבדל מ-T2:** T2 רץ על ההסלמה הספציפית; T3 עושה **hypothesis-driven hunting** מעבר לה (SANS 2025: ציד = השערה, לא סריקה).
- **🔧 clutter-risk:** היום T3 רואה `T2Console + HuntConsole + TeamIntel + ActivityLog` — ארבעה פאנלים מוערמים. היעד: hunt-board דומיננטי, שאר משני/מקופל (עקרון 1).

### 5.b איך מנטר (monitor)

על ה-**Azure-AD Global-Admin chain** (AiTM token-theft → `Add member to role: Global Administrator` מ-IP חדש → OAuth-consent זדוני → mail-forwarding rule): T3 מנטר את ה-elevation שהגיע מ-T2, ואז מנסח **hypothesis** ("משתמש שהתווסף ל-Global-Admin ביצע persistence נוסף"). מנטר את הפיד ל-`Operation:"Add-MailboxPermission"`, `Set-Mailbox …ForwardingSmtpAddress`, `Consent to application`.

### 5.c איך אוסף אינדיקטורים (collect indicators)

1. pivot על ה-actor בפיד (🔜 filter-to-actor) → מוצא forwarding-rule + OAuth-grant.
2. מוודא impossible-travel: `ActorIpAddress` + `_source.GeoLocation.country_name` מול login-history.
3. לכל ממצא: `hunt.logged {hypothesis, finding, technique}` (✅).
4. קובע scope סופי: {identities:1, apps:1, persistence:[forwarding, role]} → 🔜 `scope.confirmed` (או Amend & return ל-T2).

- **טוב:** השערה ממוקדת · ציד שמניב persistence שלא היה בהסלמה · ייחוס מדויק (T1098, T1114.003, T1528).
- **חלש:** "סורק הכל" בלי השערה · hunt בלי finding מתועד.

### 5.d איך מעביר דו"ח / hand-off

**הפעולה:** `hunt.logged` (✅) → מופיע ב-`ActivityLog` לכל הצוות. 🔜 `scope.confirmed` → מזין את החלטת-ה-Lead; `containment.requested` (חבילת-eradication) → Lead; הנחיה ל-T2 (`note.added`). **hand-off שלם** = scope מאושר + רשימת-persistence + חבילת-eradication מומלצת.

### 5.e מצבים (states)

| מצב | copy |
|---|---|
| empty hunt | "Beyond the queue: form a hypothesis, hunt the feed, record what you found." (✅) |
| no escalations | (משותף T2Console) "Nothing escalated yet." |
| logged | הממצא מופיע ב-`ActivityLog` "logged a hunt finding (T1021.002)" |

### 5.f מדדי-הצלחה — כרטיס T3 (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | final scope accuracy | כל הישויות | ≥80% | 50–79% | <50% | `scope.confirmed` (🔜) vs answer-key |
| 2 | hunt-yield | ≥1 persistence חדש | ממצא חלקי | חזר על הידוע | 0 | `hunt.logged` count + novelty |
| 3 | time hypothesis→conclusion | ≤10′ | ≤20′ | ≤30′ | לא הגיע | Δ(`hunt.logged`→`scope.confirmed`) |
| 4 | technique attribution | כל ה-techniques נכון | חוסר אחד | גס | שגוי | `hunt.logged.technique` vs MITRE |
| 5 | guidance to T2 | ממוקדת+מנומקת | כללית | מועטה | השתלט | `note.added`/`message.sent` (🔜 מדידה) |

- **NICE:** PR-CDA-001 + AN-TWA-001 (חלקי).

---

## 6. Incident Lead (`lead`) — ✅ built (`LeadConsole`)

**המשימה:** single-source-of-truth — לתאם, להחליט, לאשר הכלה, לעדכן. **לא לחקור בעצמו.**

### 6.a מה רואה על המסך (screen)

```
RIGHT PANEL — Incident Lead
┌────────────────────────────────────────────────┐
│ 🛡 Containment approvals (2)                     │
│ ┌────────────────────────────────────────────┐  │
│ │ Contain host                               │  │  ← target
│ │ Trojanized PuTTY… · requested by Rani       │  │  ← reason · requester
│ │ [ ✓ Approve ]   [ Deny ]                    │  │  ← containment.approved / .denied
│ └────────────────────────────────────────────┘  │
└────────────────────────────────────────────────┘
  + Shared Case: status stepper + assign owner (canAssign) ✅
  🔜 target: Situation Board · Decision Log · cadence timer · SITREP · Mgmt channel
```

- **role-gated חשוב (🔧 divergence):** לפי §3.7, ל-Lead **אין** raw-log מלא ("פתיחת raw-log מלא: Lead ❌"). **בבילד היום כולם — כולל Lead — רואים את ה-`EventFeed` המלא** עם raw. זו סטייה מהמאסטר (ראה §10 שורה G-08). היעד: ל-Lead תצוגת-סיכומים (Situation Board), לא raw.
- **מה קיים (✅):** approval-queue + status-stepper + assign-owner ב-`SharedCase`.
- **מה חסר (🔜):** Situation Board (כל התיקים+SLA); Decision Log (`decision.logged` — הגייט מתיר, אין UI שפולט); cadence-timer; SITREP (4 שאלות → `sitrep.sent`); Mgmt channel.

### 6.b איך מנטר (monitor)

ה-Lead מנטר את **תור-האישורים** + ה-**Shared Case** (status/owner/scope) + ה-`ActivityLog`. הוא **לא** קורא raw. על ה-PuTTY-chain: רואה את בקשת-ההכלה מ-T2, וחייב לשאול "מה ה-impact" לפני אישור (האם FIN-WS-07 הוא שרת-הפקה?).

### 6.c איך אוסף אינדיקטורים (collect indicators)

ה-Lead **לא אוסף אינדיקטורים גולמיים** — הוא צורך את הסיכומים שהצוות מייצר: ה-scope ב-Shared Case, ה-`intel.published` ב-`TeamIntel`, ה-`hunt.logged` ב-`ActivityLog`. זו הנקודה: אם ה-Lead "צולל" ל-raw — הוא מפסיק לתאם (anti-pattern §3.3).

### 6.d איך מעביר דו"ח / hand-off

**הפעולה:** `containment.approved` / `containment.denied {event_id, reason}` → T2/T3. 🔜 `decision.logged {decision, reason}` (הגייט כבר מתיר ל-lead/mgr); `case.status_set` / `case.assigned` (✅ ב-Shared Case); `sitrep.sent` (הנהלה). **hand-off שלם** = החלטה + נימוק + זמן, מתועדת.

### 6.e מצבים (states)

| מצב | copy |
|---|---|
| no requests | "No requests waiting. Tier-2 asks you to approve containment here." (✅) |
| decided | הבקשה נעלמת מהתור (מסונן ב-`contDecided`) |
| error | `action_not_allowed` אם לא-lead |

### 6.f מדדי-הצלחה — כרטיס Lead (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | `team.organized` (🔜) | ≤5′ | ≤8′ | ≤12′ | לא סומן | milestone timestamp |
| 2 | time-to-approval + correctness | ≤3′ + נכון | ≤7′ נכון | מאוחר/נימוק חלש | host תמים | Δ(`containment.requested`→`.approved`) + correctness |
| 3 | decision log (🔜) | כל DECISION עם נימוק+זמן | חוסר נימוק | בודדות | לא תיעד | `decision.logged` completeness |
| 4 | cadence + SITREP (🔜) | כל 20–30′ + 4 שאלות | פספוס אחד | חלקי | לא עדכן | `sitrep.sent` intervals |
| 5 | management pressure (🔜) | טיפל בכל injects | פספוס אחד | חלש | נכנע/הדליף | inject-response events |

- **NICE:** PR-CIR-001 (מנהיגות) + OV-MGT-001 (חלקי).

---

## 7. Detection Engineer (`de`) — ✅ built (`DEConsole`) · 🔧 keyword-only

**המשימה:** לסגור פערי-זיהוי תוך כדי האירוע — לכתוב כלל שנבדק live על הפיד.

### 7.a מה רואה על המסך (screen)

```
RIGHT PANEL — Detection engineering
┌────────────────────────────────────────────────┐
│ ⚙ Detection engineering                         │
│ Write a rule mid-incident. It back-tests live.   │
│ Rule name: ____________________________________  │  ← f.name
│ Match keyword: [ PuTTY | Global Administrator ]  │  ← f.keyword  (🔧 substring only)
│  back-test: matches 3 logs in the feed           │  ← live count (matches)
│ MITRE technique (optional): T1059.001 __________  │  ← f.technique
│ [ Publish rule ]                                 │  ← rule.published (primary CTA)
│ ─────────────────────────────────────────────── │
│ Published:  Encoded-PS-catch · matched 3          │  ← published list
└────────────────────────────────────────────────┘
```

- **role-gated:** DE כותב/מפרסם כללים; לא מאשר containment, לא מבצע triage.
- **🔧 needs-work:** ה-backtest הוא **substring keyword** על `description + event_type + raw + mitre_technique` — לא predicate/field-based. המאסטר §3.4 רוצה שפת-`eventSearch` predicates (`process.name="putty.exe" AND signed=false`) → בעתיד KQL/SPL-lite. גם: `publish` לא מייצר alert חדש בפיד לכולם ("SIEM-CUSTOM-xxx") — רק נרשם.

### 7.b איך מנטר (monitor)

DE עוקב אחרי מה שהצוות רודף דרך ה-`ActivityLog` וה-`TeamIntel`. על ה-PuTTY-chain: T2/T3 חשפו Kerberoasting → DE מנטר את הפיד לדפוס `4769 RC4 burst`.

### 7.c איך אוסף אינדיקטורים (collect indicators)

DE לא אוסף אינדיקטורים לתיק — הוא **מזקק אותם לכלל**. כותב keyword (היום) / predicate (יעד) → רואה live back-test count → מכייל עד 0 FP → מפרסם.

### 7.d איך מעביר דו"ח / hand-off

**הפעולה:** `rule.published {name, keyword, technique, matched}` (✅) → מופיע ב-`ActivityLog` "published detection rule … (N matches)". 🔜 `rule.tuned`; דיווח coverage-gap ל-Lead. **hand-off שלם** = כלל צר + מה הוא תופס + 0 FP.

### 7.e מצבים (states)

| מצב | copy |
|---|---|
| empty | "Write a rule mid-incident. It back-tests live against the feed." (✅) |
| keyword typed | "back-test: matches N logs in the feed" (ירוק אם N>0) |
| published | נכנס לרשימת Published עם `matched` |

### 7.f מדדי-הצלחה — כרטיס DE (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | verifiable rule | נתפס ב-backtest + בפועל | backtest בלבד | לא נתפס | לא פורסם | `rule.published` + `matched` |
| 2 | FP-rate | 0 FP | 1–2 | 3–5 | מציף | matched vs ground-truth |
| 3 | time-to-publish | ≤5′ מבקשה | ≤10′ | ≤20′ | >20′ | Δ(request→`rule.published`) |
| 4 | coverage-delta ATT&CK | ≥2 techniques | 1 | ניסה | 0 | technique before/after |
| 5 | documentation | כלל מוסבר | חלקי | שם בלבד | ריק | `rule.published` payload |

- **NICE:** PR-CDA-001 + AN-TWA-001 (חלקי).

---

## 8. Threat Intel (`ti`) — ✅ built (`TIConsole`)

**המשימה:** להפוך IOCs להקשר — actor/technique, next-step, מה לחסום.

### 8.a מה רואה על המסך (screen)

```
RIGHT PANEL — Threat intel
┌────────────────────────────────────────────────┐
│ 🚨 Threat intel                                 │
│ Turn indicators into context for the team.       │
│ Actor / campaign: _____________________________  │  ← f.actor
│ Technique / TTP: ______________________________  │  ← f.technique
│ Next expected step (predict): T1048 (exfil) ____  │  ← f.next_expected
│ Recommended action: ______________  [conf med ▼] │  ← f.recommendation · confidence
│ [ Publish intel ]                                │  ← intel.published (primary CTA)
└────────────────────────────────────────────────┘
   → renders to everyone in the shared "Team intel" card ✅
```

- **role-gated:** TI מפרסם intel notes (מופיע ל-כולם ב-`TeamIntel`); מציע IOCs — ה-Lead מאשר; לא מבצע containment.
- **🔧:** חסר שדה `relevance` (§3.5) ומאגר-intel/advisory-inject (🔜). מבוסס על ה-`ThreatIntelDrawer` הקיים לחיפוש hash/ip/domain.

### 8.b איך מנטר (monitor)

TI עוקב אחרי האינדיקטורים של האירוע דרך ה-`ActivityLog`, ה-Shared Case scope, וה-`ThreatIntelDrawer` (מפיד היחיד). על ה-PuTTY-chain: מזהה שה-hash+C2 תואמים ל"קמפיין" מוכר.

### 8.c איך אוסף אינדיקטורים (collect indicators)

לוחץ **Check Hash/IP/Domain** בפיד → `ThreatIntelDrawer` → אוסף verdict/reputation → מזקק ל-actor/technique עם confidence מפורש → מנבא את השלב-הבא (`T1048` exfil ל-mega.nz, לפני inject #14).

### 8.d איך מעביר דו"ח / hand-off

**הפעולה:** `intel.published {actor, technique, confidence, recommendation, next_expected}` (✅) → כרטיס ב-`TeamIntel` לכולם. **hand-off שלם** = note קצר עם confidence מפורש, **לפני** שהשלב-הבא קורה.

### 8.e מצבים (states)

| מצב | copy |
|---|---|
| empty | "Turn indicators into context for the team." (✅) |
| published | כרטיס מופיע ב-`TeamIntel` (הפאנל מוסתר עד שיש ≥1 intel) |
| disabled CTA | עד ש-`actor` או `technique` מלא |

### 8.f מדדי-הצלחה — כרטיס TI (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | actionable-rate | ≥80% הובילו לפעולה | 60–79% | 40–59% | <40% | `intel.published`→פעולה עוקבת |
| 2 | time-to-action | note לפני שהשלב קרה | ≤5′ אחרי | מאוחר | לא רלוונטי | Δ(note→שלב) |
| 3 | attribution accuracy | actor+technique נכון | technique בלבד | גס | שגוי | payload vs ground-truth |
| 4 | next-step prediction | נכון לפני שקרה | באיחור | גס | לא ניבא | `next_expected` vs בפועל |
| 5 | IOC-precision | 0 שגויים | 1 | 2–3 | הציף | proposed-IOC vs answer-key |

- **NICE:** AN-TWA-001; NIST RS.CO.

---

## 9. SOC Manager / Shift Lead (`mgr`) — ✅ built (`MgrConsole`)

**המשימה:** עומס, SLA, עדיפויות, מסירת-משמרת.

### 9.a מה רואה על המסך (screen)

```
RIGHT PANEL — Shift management
┌────────────────────────────────────────────────┐
│ 👥 Shift management                             │
│  Dana   Tier-1        6 actions                  │  ← workload (actions/analyst)
│  Rani   Tier-2        4 actions                  │
│  Noa    Tier-3        3 actions                  │
│ ─────────────────────────────────────────────── │
│ Shift / handover note: ________________________  │  ← note (≥5 תווים)
│ [ Post handover note ]                           │  ← handover.noted (primary CTA)
└────────────────────────────────────────────────┘
   🔜 target: SLA-breach flags · re-assign · priority · passdown fields (App. D)
```

- **role-gated:** Mgr מנהל עומס/SLA/עדיפויות; חותם handover; מאשר containment רק אם Lead נותק (§3.7 הערה \*). אין raw-log מלא (כמו Lead — 🔧 היום כן רואה).
- **🔧:** ה-workload = ספירת-actions גולמית (`events.filter(actor_id === m.user_id …).length`), לא alerts/analyst + SLA-breaches. אין re-assign/priority. `handover.noted` = טקסט חופשי, לא פורמט App. D (on-duty · open cases {id,sev,last,next} · blockers).

### 9.b איך מנטר (monitor)

Mgr מנטר את ה-**workload board** (מי עמוס), ה-`ActivityLog` (שהסלמות לא תקועות), וה-Shared Case status. על תרחיש עם second-incident (password-spray על VPN): מזהה ש-T1 עמוס → יעד: re-assign / T1 שני.

### 9.c איך אוסף אינדיקטורים (collect indicators)

Mgr לא אוסף אינדיקטורים טכניים — הוא אוסף **אינדיקטורי-בריאות-משמרת**: פער-עומס בין analysts, escalations ללא ack, SLA-breaches (🔜).

### 9.d איך מעביר דו"ח / hand-off

**הפעולה:** `handover.noted {summary}` (✅) → `ActivityLog` "posted a handover note". 🔜 `passdown.signed` (פורמט B); re-assign (`case.assigned`); elevation. **hand-off שלם** = passdown עם open cases + next-step + deadline + blockers → הצוות-הבא ממשיך בלי לשאול.

### 9.e מצבים (states)

| מצב | copy |
|---|---|
| workload empty | הרשימה ריקה עד שיש roster |
| note too short | CTA disabled עד `≥5` תווים |
| posted | `note` מתאפס, מופיע ב-`ActivityLog` |

### 9.f מדדי-הצלחה — כרטיס Mgr (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | SLA-adherence | 0 breaches | 1 | 2–3 | >3 | SLA timers vs `event.opened`/`disposition.set` (🔜) |
| 2 | workload balance | פער נמוך | בינוני | גבוה | analyst קורס | actions/analyst distribution |
| 3 | passdown | כל שדות App. D + next+deadline | חוסר שדה | חלקי | לא חתם | `handover.noted`/`passdown.signed` payload |
| 4 | reopen-rate | 0 | 1 | 2 | >2 | `case.status_set` reopens |
| 5 | elevation correctness | בזמן+מוצדק | מאוחר | מיותר | פספס | elevation events (🔜) |

- **NICE:** OV-MGT-001 (חלקי) + MITRE "SOC leadership".

---

## 10-A. Instructor (`instructor` / staff) — ✅ built (`InstructorPanel`)

**המשימה:** להריץ את התרגיל — לנטר כל תפקיד, לסיים ולחשוף את הדו"ח.

### a. מה רואה על המסך (screen)

```
RIGHT PANEL — Instructor view                    (+ top strip: End exercise)
┌────────────────────────────────────────────────┐
│ 🛡 Instructor view                              │
│  ● Dana   Tier-1                                 │  ← roster + presence dots
│  ● Rani   Tier-2                                 │
│  ○ Noa    Tier-3   (offline)                     │
│  ● Amir   Incident Lead                          │
└────────────────────────────────────────────────┘
   top strip: [ ? Guide ]  [ End exercise ]  ✅
   🔜 target: MSEL timeline · inject composer · pressure dials · "stuck team" alert · SA board
```

- **role-gated:** ה-instructor/staff רואה `InstructorPanel` + **כל** הפיד + Shared Case; שולט ב-Start (בלובי) וב-End-Ex. הוא Exercise Director, לא נגן (מאסטר §1.4.4).
- **🔧/🔜:** היום רק roster+presence + End. חסר: MSEL timeline (scheduled/fired/skipped), inject-composer (persona+channel+body), pressure-dials (feed-rate/SLA/pause), "stuck team" heuristic, multi-room tabs, Override-ניקוד ב-hot-wash.

### b. איך מנטר (monitor)

ה-`InstructorPanel` (presence per-role) + ה-`ActivityLog` (כל הקואורדינציה) + Shared Case status. היעד: **Team SA board** — פעולה-אחרונה לכל תפקיד + ack-clocks אדומים + "צוות תקוע?" heuristic.

### c. איך אוסף אינדיקטורים

ה-instructor לא אוסף אינדיקטורי-אירוע — הוא אוסף **אינדיקטורי-תרגיל**: מי online, מי תקוע, האם הסלמות נענות, קצב-ההתקדמות של ה-Shared Case.

### d. איך מעביר דו"ח / hand-off

**הפעולה:** `session.started` (Start, בלובי) ו-`session.ended` (End-Ex) — דרך ה-API routes (`/start`, `/end`), לא דרך `apply_session_action` (system-only ב-gate). End → מפיק `TeamReport` (per-user + team + CSV). 🔜 inject-composer יפלוט `inject.fired`; override יפלוט `grade.overridden`.

### e. מצבים (states)

| מצב | copy |
|---|---|
| lobby not-all-ready | "Locked until every player marks ready." (✅) |
| all ready | "All players are ready." → כפתור Start נדלק |
| running | End-Ex זמין |
| ended | `TeamReport` נחשף |

### f. מדדי-הצלחה

ה-instructor **לא מנוקד** (measured: "—" ב-`ROLE_GUIDE`). המדד שלו הוא איכות-ה-hot-wash (מאסטר §6.6) — 🔜.

---

## 11. מפרט-מדידה — זמנים וקליקים (Measurement spec — times & clicks)

> התחזוקן ביקש במפורש **"למדוד זמנים וקליקים"**. כל מדד נגזר מ-`session_events` (`occurred_at` + `type` + `payload`). "נכון-להיום" = מה שבאמת נלכד בבילד; "פער" = מה שצריך להוסיף.

### 11.1 מדדי-זמן (Time metrics)

| מדד | הגדרה / נוסחה מ-`session_events` | יעד / חלון-סובלנות | סטטוס בבילד |
|---|---|---|---|
| **MTTA** (alert→first open) | Δ( `feed.event.occurred_at` של האירוע → ה-`event.opened` הראשון אחריו ) | ≤2′ high/crit | 🔧 `event.opened` נפלט אך **ללא `event_id`** — לא ניתן לשייך לאירוע |
| **time-to-triage** | Δ( `feed.event` → `disposition.set{event_id}` ) | ≤5/10/15′ | ✅ (`disposition.set` נושא `event_id`) |
| **time-to-escalate** | Δ( `feed.event` → `escalation.requested{event_id}` ) | ≤10′ | ✅ |
| **ack-latency** | Δ( `escalation.requested` → `escalation.acknowledged` (אותו `event_id`) ) | ≤2/5/10′ | ✅ |
| **time-to-approval** | Δ( `containment.requested` → `containment.approved` (אותו `event_id`) ) | ≤3/7′ | ✅ |
| **time-to-contain** (MTTC) | Δ( first attack `feed.event` → `containment.approved` / 🔜 `containment.executed` ) | מול יעד-קושי | 🔧 approved קיים; `executed`/beacon-stop 🔜 |
| **time-to-detect** (MTTD) | Δ( `session.started` → first `escalation.requested` על attack-event ) | מול יעד-קושי | ✅ (`computeReport.timeToDetectS`) |
| **per-log dwell** | `event.opened.dwell_ms` (זמן-שהייה בשורה שנפתחה) | — (thoroughness) | 🔜 **ה-payload ריק** — dwell לא נמדד כלל |
| **first-action** | Δ( `session.started` → הפעולה הראשונה של המשתמש ) | — | ✅ (`firstActionS`) |

**חוֹר-המדידה הקריטי (🔧 חובה לתקן):** `onRowOpened={() => act("event.opened", {})}` פולט payload **ריק**. בלי `event_id` ו-`dwell_ms`, אי-אפשר לחשב MTTA-אמיתי, "איזה לוג נפתח", או per-log dwell (playbook §10 שאלה 4 מדגיש זאת). התיקון: `onRowOpened={(id, dwellMs) => act("event.opened", { event_id: id, dwell_ms: dwellMs })}` + ה-`EventRow` מודד dwell מ-expand ל-collapse.

### 11.2 טלמטריית-קליק / פעולה (Click / action telemetry)

| קליק/פעולה | event שנלכד | payload | מתגלגל ל- | סטטוס |
|---|---|---|---|---|
| פתיחת שורת-לוג | `event.opened` | `{}` 🔧 (יעד: `{event_id, dwell_ms}`) | contribution (`opened*3`) · MTTA · thoroughness | 🔧 |
| filter/pivot | `filter.applied` / `pivot.used` | 🔜 | investigation depth | 🔜 (ה-feed hardcoded `"all"`) |
| disposition | `disposition.set` | `{event_id, verdict}` | disp-accuracy · time-to-triage | ✅ |
| escalation | `escalation.requested`/`.acknowledged` | `{event_id, what, why, impact, confidence}` | esc-quality · ack-latency | ✅ |
| containment | `containment.requested`/`.approved`/`.denied` | `{event_id, target, reason}` | time-to-approval · MTTC | ✅ (🔜 `.executed`) |
| note | `note.added` | `{text}` | documentation · contribution | ✅ |
| evidence | (evidence = escalations) 🔧 | — | scope · Shared Case | 🔧 (יעד: `evidence.pinned` מפורש) |
| rule | `rule.published` | `{name, keyword, technique, matched}` | DE rubric · contribution | ✅ 🔧 (keyword-only) |
| intel | `intel.published` | `{actor, technique, confidence, recommendation, next_expected}` | TI rubric · TeamIntel | ✅ |
| hunt | `hunt.logged` | `{hypothesis, finding, technique}` | T3 hunt-yield | ✅ |
| handover | `handover.noted` | `{summary}` | Mgr passdown | ✅ 🔧 (טקסט חופשי) |
| case status/owner | `case.status_set` / `case.assigned` | `{status, severity}` / `{owner}` | case progression | ✅ |
| war-room message | `message.sent` | 🔜 | coordination | 🔜 (גייט מתיר, אין UI) |

**איך זה מתגלגל ל-CSV/AAR:** `computeReport()` גוזר per-user `{opened, dispCount, dispAcc, escCount, escQuality, acks, contReq, contDecided, roleActions, firstActionS, contribution}` ו-`exportCsv()` מייצא אותם. **הפער:** ה-`contribution` היום הוא נוסחת-משקל גולמית (0–100), **לא** כרטיס-5-הקריטריונים (0/4/8/12) של §6.3 — ראה §10 שורה G-11.

---

## 12. האירוע כ-relay — דוגמה מקצה-לקצה

טבלת-relay אחת של ה-PuTTY-trojan chain: איך הכרטיס מעמיק tier-אחר-tier, ואיך הציונים מצטברים. (offset = דקות מ-`session.started`.)

| offset | role | מה רואה | מה לוחץ | מה פולט (event) | מי מקבל |
|---|---|---|---|---|---|
| 00:02 | T1 | `feed.event` high על FIN-WS-07 | מרחיב שורה + Raw log | `event.opened` (🔧 +event_id) | — |
| 00:03 | T1 | raw: parent=WINWORD, unsigned, `-enc` | disposition | `disposition.set{TP}` | ground-truth (ניקוד) |
| 00:04 | T1 | טופס-הסלמה | Escalate | `escalation.requested{what,why,impact,conf}` | T2 (inbox) |
| 00:05 | T2 | הסלמה בתור | Acknowledge | `escalation.acknowledged` | T1 (`ActivityLog`) |
| 00:09 | T2 | 🔜 עץ-תהליכים ב-EDR | 🔜 Investigate in EDR | 🔜 `edr.opened` / scope | T3 (elevation) |
| 00:12 | T3 | hunt-board + פיד | Log hunt finding | `hunt.logged{2nd beacon, T1021}` | הצוות (`ActivityLog`) |
| 00:15 | TI | IOCs + ThreatIntelDrawer | Publish intel | `intel.published{next: T1048}` | כולם (`TeamIntel`) |
| 00:16 | T2 | scope מלא | Request containment | `containment.requested{target,reason}` | Lead (approvals) |
| 00:18 | Lead | בקשת-הכלה + scope | Approve | `containment.approved` (🔜 `decision.logged`) | T2 |
| 00:20 | T2 | אישור | 🔜 execute isolate | 🔜 `containment.executed` → beacon עוצר | הפיד (כולם) |
| 00:22 | DE | טכניקה שנחשפה | Publish rule | `rule.published{matched}` | הצוות (`ActivityLog`) |
| 00:26 | Lead | תמונת-מצב | set status → contained | `case.status_set{contained}` | Shared Case (כולם) |
| 00:30 | Mgr | עומס + סוף-משמרת | Post handover | `handover.noted{summary}` | הצוות-הבא |

**איך הציונים מצטברים (מ-`computeReport` + §6.2):**

| רכיב-צוות | משקל | מה מהטבלה מזין אותו |
|---|---|---|
| Detection & Containment | 30 | `timeToDetectS` (00:04) · MTTC (00:16→00:18) · kill-chain-depth בעת containment (לפני exfil) |
| Escalation & handoff | 20 | `escQuality` (00:04) · ack-latency (00:04→00:05) · 0 אבודות |
| Coordination & communication | 15 | `decision.logged` (00:18, 🔜) · אין עבודה-כפולה · cadence (🔜) |
| Reports & documentation | 20 | `report.graded` (🔜) · `note.added` · `handover.noted` (00:30) |
| Timeliness & SLA | 15 | time-to-triage (00:02) · time-to-approval (00:16→00:18) |

> ציון-צוות אחד משותף; כל תפקיד + כרטיס-אישי-פרטי. **אין ניקוד חי** — נחשף רק ב-`TeamReport` אחרי End-Ex.

---

## 13. Per-role at-a-glance

| role | מסך ראשי | מנטר | אוסף אינדיקטורים דרך | מדווח (action) | 3 קריטריונים מובילים | תנאי-ניצחון |
|---|---|---|---|---|---|---|
| **T1** | `T1Console` — pick-log + disposition + escalate | הפיד (severity/time) | הרחבת-שורה → Raw → MITRE → ThreatIntelDrawer | `escalation.requested` → T2 | disp-accuracy · esc-precision · card-completeness | הסלמה שלמה שאושרה, FP נסגר עם נימוק |
| **T2** | `T2Console` — inbox → ack → request | inbox + Shared Case | 🔜 EDR + pivot בפיד | `containment.requested` → Lead | ack-latency · scoping · containment-rec | scope נכון + הכלת ה-host הנכון בזמן |
| **T3** | `T2Console` + `HuntConsole` | elevation + פיד | 🔜 full EDR + pivot; hunt-board | `hunt.logged` (🔜 `scope.confirmed`) → Lead/TI/DE | scope · hunt-yield · attribution | חשף persistence נוסף + scope מלא |
| **Lead** | `LeadConsole` + Shared Case stepper | approvals + Shared Case (לא raw) | סיכומי-צוות (scope/intel/hunt) | `containment.approved` (🔜 `decision.logged`) → T2/T3 | time-to-approval · decision-log · cadence | תיאם, אישר נכון עם נימוק, עדכן בזמן |
| **DE** | `DEConsole` — keyword back-test | `ActivityLog` + פיד | back-test count | `rule.published` → הצוות | verifiable-rule · FP-rate · coverage | כלל צר שתופס את השלב-הבא, 0 FP |
| **TI** | `TIConsole` — intel note | scope + ThreatIntelDrawer | Check Hash/IP/Domain | `intel.published` → כולם | actionable · prediction · IOC-precision | note עם confidence שהוביל לפעולה, מוקדם |
| **Mgr** | `MgrConsole` — workload + handover | workload board + `ActivityLog` | אינדיקטורי-בריאות-משמרת | `handover.noted` → הצוות-הבא | SLA · workload-balance · passdown | 0 SLA-breaches + passdown שממשיך בלי שאלות |
| **Instructor** | `InstructorPanel` + End | roster/presence + `ActivityLog` | אינדיקטורי-תרגיל | `session.started/ended` (API) | — (לא מנוקד) | תרגיל שרץ חלק + hot-wash מלמד |

---

## 14. Gap analysis — הבילד הנוכחי מול היעד

> זה החלק שמניע את התיקון. כל שורה: {area · current (as coded) · target · severity · effort · fix note · tag}. Severity: 🔴 high (פוגע בליבת-החוויה/המדידה) · 🟠 med · 🟡 low. Effort: S/M/L.

| # | area | current (as coded) | target | sev | eff | fix note | tag |
|---|---|---|---|---|---|---|---|
| G-01 | **click telemetry** | `event.opened` נפלט עם payload **ריק** `{}` | `{event_id, dwell_ms}` — dwell נמדד מ-expand→collapse | 🔴 | S | ה-`EventRow` כבר יודע מתי נפתח; להוסיף `event_id`+טיימר ולהעביר ל-`onRowOpened` | ✅ מומש (EventFeed onRowOpened(eid,dwell); report: distinct-opened + avg-dwell) |
| G-02 | **Shared Case hierarchy** | full-width **מעל** ה-grid; דוחף את הפיד מטה, מתחרה על תשומת-לב | סרגל-סיכום דק collapsible (status·owner·scope) שנפתח לפירוט בלחיצה | 🔴 | M | הפיד הוא האמת (עקרון 2); ה-case משני | ✅ מומש (SharedCase collapsible summary-bar) |
| G-03 | **right-column clutter** | T3 מקבל `T2Console+HuntConsole+TeamIntel+ActivityLog` מוערמים; כולם רואים ≥3 פאנלים בימין | פאנל-תפקיד דומיננטי אחד; TeamIntel/ActivityLog מקופלים/tab | 🔴 | M | עקרון 1 role-focus; להפוך את ה-secondary ל-accordion/tabs | ✅ מומש (SecondaryPanels: "Team context" accordion + tabs) |
| G-04 | **feed filters not surfaced** | `EventFeed` בחדר-הצוות עם `severityFilter="all" sourceFilter="all" search=""` קבוע | לחשוף severity/source/search + **click-to-pivot** (לחיצה על host/user/IP → filter) | 🔴 | M | ה-`EventFeed` כבר תומך ב-props האלה; רק לחווט + כפתורי-pivot ב-`DetailPanel` | ✅ מומש (FeedFilterBar + onPivot chip; אומת 5→2 events) |
| G-05 | **EDR not wired for T2/T3** | אין כפתור "Investigate in EDR"; `/edr` קיים אך לא מקושר מחדר-הצוות | כפתור פותח `/edr` על ה-host, טעון בעץ-התהליכים; חוזר עם ראיה | 🔴 | L | `SPEC-edr-console.md`; deep-link + חזרה לתיק | ✅ מומש (כפתור ב-T2/T3 → `buildInvestigationFromStory` על טלמטריית-הצוות → stash + `/edr?case=live&team=<id>`; ה-`?team` עוקף את bounce ה-`isTrainingActive`; null-fallback גרייספול לתקיפת-זהות ללא endpoint. happy-path תלוי-דאטה: דורש סטורי endpoint עם process.pid) |
| G-06 | **DE back-test keyword-only** | substring על description+event_type+raw+mitre | predicate/field-based (`eventSearch`) → KQL/SPL-lite; publish מייצר alert בפיד | 🟠 | L | keyword מספיק ל-MVP; predicate הוא היעד (§3.4) | ✅ מומש (DEConsole משתמש ב-`eventMatchesSearch` על liveFeed — `field:value` AND-ים: source/host/user/ip/mitre/rule/vendor/event/severity + תצוגת-התאמות. publish→alert-בפיד = follow-up שרת) |
| G-07 | **escalation schema shallow** | `event_id` יחיד; `why≥10 תווים`; אין `evidence_ids[]`/`requested_action`/states accepted/bounced/resolved | ריבוי-ראיות · `why≥20 מילים` · requested_action · state-machine מלאה | 🟠 | M | §5.2/נספח-א׳; מוסיף feedback-loop ל-T1 | ✅ מומש (0058 `escalation.bounced`/`escalation.resolved`; T1 מוסיף requested_action; escQualityScore מתגמל why≥20-מילים+requested_action; T2 Bounce/Resolve; T1 רואה "Bounced back to you". ריבוי-ראיות evidence_ids[]=follow-up) |
| G-08 | **Lead sees raw feed** | כולם — כולל Lead/Mgr — רואים `EventFeed` מלא עם raw | Lead/Mgr מקבלים Situation Board (סיכומים), **לא** raw (§3.7) | 🟠 | M | תפקיד=הגבלה; מונע "Lead שצולל" | ✅ מומש (SituationBoard ל-lead/mgr לא-staff: pulse+top-sources+escalation-queue, ללא raw) |
| G-09 | **containment not executed** | `containment.approved` — אין `.executed`/beacon-stop; אין shared containment state | approve→T2 executes→`containment.executed`→beacon עוצר בפיד לכולם | 🟠 | L | חלק מ-EDR integration (G-05); MTTC אמיתי תלוי בזה | ✅ מומש (0057 `containment.executed` t2/t3; "Execute isolation" מופיע כשמאושר-וטרם-בוצע; Shared-Case מציג "Isolation executed"; MTTC=Δ(request→executed) בדו"ח. beacon-suppression בפיד = follow-up) |
| G-10 | **scope is auto-only** | scope ב-Shared Case נגזר-אוטומטית מההסלמות; אין `scope.set`/`scope.confirmed` של T2/T3 | T2 קובע scope, T3 מאשר/מתקן (Confirm/Amend) | 🟠 | M | הופך את T3 למובחן מ-T2; מזין ניקוד-scope | ✅ מומש (0057 `scope.set` t2/t3 + `scope.confirmed` t3; ScopeConsole set/confirm; Shared-Case מעדיף scope מפורש עם badge proposed/confirmed; מזין רובריקת T2#3 + T3#1) |
| G-11 | **scoring = raw contribution** | `contribution` 0–100 נוסחת-משקל; אין כרטיס-5-קריטריונים 0/4/8/12 | רובריקת per-role (§6.3) גלויה בדו"ח + בלובי | 🟠 | M | לאחד סולם (§11 שאלה); ה-events כבר קיימים לרובם | ✅ מומש (סולם 0/4/8/12; roleRubric ל-7 תפקידים; 🔜-criteria=n/a מחוץ ל-%; אומת DE=89) |
| G-12 | **no SLA/cadence bottom bar** | אין טיימרי-SLA לאירועי high/crit; אין cadence-timer ל-Lead | bottom-bar עם SLA-clocks (אדום כשחורג) + cadence "next update by" | 🟠 | M | §7.2; ה-timestamps כבר ב-events | ↩️ **הוסר לבקשת Tal (2026-09-15)** — מומש (SlaBar) אך הוסר מהתצוגה כי העמיס על המסך. הקוד הוסר; אפשר להחזיר. |
| G-13 | **no war-room / messaging** | הגייט מתיר `message.sent`, אין UI; אין ערוץ-הנהלה | war-room טקסטואלי (durable) + Mgmt channel ל-Lead | 🟠 | M | נדרש ל-coordination-scoring + AAR "who-knew-what-when" | ✅ מומש (WarRoom = tab שלישי ב-"Team context"; `message.sent` durable, כל הצוות רואה; אומת שליחה+רינדור. Mgmt-channel נפרד = follow-up) |
| G-14 | **no help-desk / injects / personas** | אין `ticket.answered`, אין inject-composer, אין SimCell | ticket-channel ל-T1 · inject-composer למדריך · personas | 🟡 | L | §5.4/§5.5; שלב-2 | ✅ מומש (0058 `staff.inject`/`ticket.answered`; InstructorPanel inject-composer=announcement/ticket/mgmt_pressure; InjectFeed לכולם; T1 עונה Handle/Reject-vishing → מזין רובריקת T1#5. SimCell-personas=follow-up) |
| G-15 | **no SITREP / decision-log / passdown UI** | הגייט מתיר `decision.logged`; אין UI. אין `sitrep.sent`/`passdown.signed` | Lead: Decision Log + SITREP (4 שאלות); Mgr: passdown (App. D) | 🟡 | M | מזין Reports&Docs (20% מהציון) | ✅ מומש (0058 `sitrep.sent`; LeadConsole Decision-Log→Lead#3 + SITREP 4-שאלות→Lead#4; Mgr passdown מובנה=G-16. `passdown.signed` נפרד=handover.noted הקיים) |
| G-16 | **handover free-text** | `handover.noted{summary}` טקסט חופשי | פורמט App. D (open cases {id,sev,last,next}, blockers) | 🟡 | S | שדות-טופס במקום textarea | ✅ מומש (MgrConsole passdown מובנה: open_cases/blockers/next → `handover.noted` + text מורכב) |
| G-17 | **TI missing `relevance` + repo** | אין שדה relevance; אין intel-repository/advisory-inject | הוספת relevance + מאגר-intel נגזר-מ-story (עם IOC שגוי אחד) | 🟡 | M | §3.5; מלמד "אימות מול מקור" | ✅ מומש (TIConsole: שדה relevance high/med/low + IOC ל-intel.published; INTEL_REPO עם 3 advisories — אחד decoy (8.8.8.8) שמלמד "אמת מול המקור"; "use this IOC →") |
| G-18 | **first-action guide only** | `RoleGuideModal` פעם-אחת + directive banner | + inline nudge אחרי N דקות ללא פעולה בתפקיד | 🟡 | S | §5.8 anti-loafing; ה-events כבר זמינים | ↩️ **הוסר לבקשת Tal (2026-09-15)** — מומש (idle nudge) אך הוסר מהתצוגה כי העמיס על המסך. ה-directive banner + ה-Guide נשארו. |
| G-19 | **✅ shared feed identical + reconcile** | Broadcast-from-DB + poll-safety-net כל 6s; אף לוג לא אובד | (נשמר) | — | — | זה עובד היטב — לא לגעת | ✅ |
| G-20 | **✅ role-gated actions in DB** | `session_action_allowed` אוכף role×phase בשרת | (נשמר) | — | — | ליבת-האבטחה תקינה | ✅ |
| G-21 | **✅ gamified lobby ready-check** | presence + ready-toggle + N/N + 3-2-1 countdown + staff-start | (נשמר) | — | — | §13.11 ממומש יפה | ✅ |

**סדר-תיקון מומלץ (מונחה-severity):** G-01 (מדידה שבורה) → G-02+G-03+G-04 (חוסר-חלקוּת ה-UX, מה שהתחזוקן הרגיש) → G-08 (role-gating של Lead) → G-11 (ניקוד אמיתי) → G-05+G-09+G-10 (עומק T2/T3) → השאר לפי שלב.

**סטטוס-מימוש (2026-09-15): כל 18 הפערים הפתוחים (G-01…G-18) מומשו ✅.** מיגרציות DB: 0057 (scope.set/confirmed, containment.executed) + 0058 (escalation.bounced/resolved, staff.inject, ticket.answered, sitrep.sent) — הוחלו ואומתו על staging. G-19/20/21 היו טובים-מראש (לא נגענו). כל הקוד staging-only, לא-מקומיט; tsc נקי + 157/157 vitest. **follow-ups שרת-תלויים שנותרו (מעבר לפערים):** publish→alert-בפיד (G-06), evidence_ids[] ריבוי-ראיות (G-07), beacon-suppression בפיד (G-09), SimCell-personas (G-14), cadence-timer ל-Lead (G-12) — כולם דורשים הזרקת feed.event/טיימר-שרת ותוכננו כשלב-הבא.

---

## 15. שאלות פתוחות לטל

1. **Shared Case hierarchy (G-02):** להפוך אותו לסרגל-סיכום דק-collapsible כברירת-מחדל (המלצתי) — או שהתחזוקן רוצה שהתיק יישאר בולט full-width?
2. **סולם-ניקוד (G-11 / §3.f):** לאחד ל-**0/4/8/12** (playbook, המלצתי) או לשמור על **0/4/6/8/12** של המאסטר §6.3? צריך הכרעה לפני בניית מסך-הרובריקה.
3. **event.opened dwell (G-01):** להוסיף `{event_id, dwell_ms}` עכשיו (S, פותח את כל מדדי-הזמן) — לפני כל שאר ה-UX polish?
4. **Lead raw-access (G-08):** לאכוף שה-Lead **לא** רואה raw (§3.7), או שבסביבת-אימון עדיף שכולם יראו הכל למען שקיפות-למידה?
5. **T2/T3 split (G-10):** לבנות scope.set/scope.confirmed + קונסולת-T3 ייעודית כבר עכשיו, או להשאיר את `T2Console` המשותף + `HuntConsole` ל-MVP?
6. **EDR-in-team (G-05):** deep-link ל-`/edr` הקיים (מהיר) מול EDR-panel מוטמע בחדר-הצוות (חלק יותר, יקר) — מה עדיף?
7. **feed filters + pivot (G-04):** לחשוף את בקרות ה-`EventFeed` המלאות (severity/source/search/time) לכל התפקידים, או רק ל-T1/T2/T3 (ה-Lead ממילא לא אמור לפלטר raw)?
8. **war-room (G-13):** נדרש ל-MVP (coordination-scoring + AAR "who-knew-what-when") או שלב-2? בלעדיו ~15% מהציון (Coordination) לא ניתן-למדידה מלאה.
