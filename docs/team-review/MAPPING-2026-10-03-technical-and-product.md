# מיפוי טכני ומוצרי — Team-SOC Exercise

**תאריך:** 2026-10-03
**כותב:** מיפוי מטעם מנהל מוצר + איש סייבר טכני
**גרסה חיה:** `main 80b6d99` (פרוד) · מיגרציות DB עד `0089`
**היקף המסמך:** פיצ'ר האימון הצוותי (Team-SOC) ב-HACK THE SOC, והשתלבותו בפלטפורמה.

---

## 0. תקציר מנהלים

**מצב:** הפיצ'ר **חי בפרודקשן** ועבר deploy מאומת (health check ירוק, DB ok, אפס 5xx). זהו מנוע אימון צוותי מלא שבו אדמין-ארגון בונה משמרת, מזמין חברי צוות לתפקידי SOC (T1/T2/T3/Manager), והצוות חוקר **פיד לוגים משותף חי** מקצה-לקצה — טריאז׳, הסלמה, scoping, containment, ודו"ח סיכום לכל משתתף.

**בשורה אחת:** הארכיטקטורה חזקה ובשלה (append-only event log, server-authoritative, realtime-from-DB, שערי איכות ירוקים). פער הליבה היה **תקפות המדידה** — עד כמה המשחק מודד ניתוח אמיתי ולא "ניחוש לפי severity" — וזה טופל בגל ה-P0/P1 האחרון שעלה כעת לפרוד.

**פסק דין מקצועי (מתוך חוות הדעת, [EXPERT-OPINION.md](../qa/team-exercise-review/EXPERT-OPINION.md)):** "מוכן עם תיקונים" → רוב התיקונים בוצעו ונפרסו. ראה §5 להמלצות המשך.

---

## 1. מיפוי טכני — ארכיטקטורה

### 1.1 שכבות המערכת

```
┌─────────────────────────────────────────────────────────────┐
│  CLIENT (Next.js 15, React)                                   │
│  team/page.tsx (Session Builder) · team/[id]/page.tsx (Room)  │
│  24 רכיבים: קונסולות תפקיד + SharedCase + Feed + Report        │
└───────────────┬──────────────────────────┬──────────────────┘
                │ REST (11 routes)          │ Realtime (Broadcast+Presence)
                ▼                           ▼
┌─────────────────────────────────────────────────────────────┐
│  SERVER                                                       │
│  /api/team/* — server-authoritative, org+role gated          │
│  apply_session_action() = נתיב הכתיבה היחיד (SECURITY DEFINER)│
└───────────────┬──────────────────────────────────────────────┘
                ▼
┌─────────────────────────────────────────────────────────────┐
│  SUPABASE POSTGRES                                            │
│  session_events (APPEND-ONLY) · session_state (projection)   │
│  team_sessions · team_session_members · session_injects      │
│  RLS בכל הטבלאות · realtime.messages policies                 │
│  pg_cron: promote_due_injects · replenish_feed · lifecycle    │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 מודל הנתונים (עיקרי)

| טבלה | תפקיד | מאפיין מפתח |
|---|---|---|
| `team_sessions` | המשמרת | `schema_version` (v1/v2), `scenario_id`/`config.attacks` (תוכנית תקיפה), `config.env` (סביבה), `status`, `paused_ms` |
| `team_session_members` | רוסטר + תפקידים | role (t1/t2/t3/mgr/instructor…), status (invited/ready/active/left), `last_seen_at` (presence) |
| `session_events` | **מקור האמת — append-only** | `position` bigserial, `unique(session_id,seq)`, `unique(session,actor,idempotency_key)` |
| `session_state` | projection (seq נוכחי) | מתעדכן ע"י ה-RPC |
| `session_injects` | MSEL — תסריט הזרקות | **staff-only** (`expected_action` = ספוילר), channel feed/inject/bonus |
| `team_session_reports` | דו"ח מחושב (cache) | service-only |
| `session_clicks` | טלמטריית פתיחת-לוג | ללא broadcast (off the feed) |
| `team_ops_events` / `team_ops_health` | אבחון תפעולי | service-only |

### 1.3 נתיב הכתיבה — server-authoritative

- **`apply_session_action(session, type, payload, expected_seq, idempotency_key)`** הוא ה**נתיב היחיד** לכתיבה (ללוקוחות אין INSERT grant). אוכף:
  - חברות + `session_action_allowed(type, role, status)` — **deny-by-default** (מיגרציה 0061).
  - optimistic concurrency (expected_seq) + **seq-retry loop** (0062) נגד duplicate-key.
  - idempotency (unique session/actor/key) + rate-limit (token bucket ≈60/min) + hard cap (0071).
  - advisory lock per-session (lock-first) למניעת race.
- **Broadcast-from-DB:** טריגר AFTER-INSERT על `session_events` → `realtime.send(...)` לטופיק הפרטי `session:<uuid>` → כל החברים מקבלים את האירוע ב-~0ms. מוגן-exception כך ש-broadcast תקול לא מפיל כתיבה.
- **רשת ביטחון:** הלקוח מושך `session_events > maxSeq` כל כמה שניות + על `SUBSCRIBED`/`visibilitychange` (contiguous-watermark gap-fill), כך שאף חבר לא מפספס לוג.

### 1.4 מנוע הטיימליין ([buildTimeline.ts](../../src/lib/team/buildTimeline.ts))

דטרמיניסטי ואיזומורפי (seed → אותו פיד תמיד; גם ה-lobby מציג לאדמין את אותם מספרים):

1. **סביבה → ארסנל:** `teamStoryPool(company, difficulty, env, stack)` — הסטורי-ליינים והלוגים נגזרים מבחירת הסביבה (8 פלטפורמות) והמוצרים (stack), לא מתבנית קבועה.
2. **תוכנית תקיפה:** עד 3 slots (storyline נבחר או Random) + **bonus attack** בברירת מחדל ([attackPlan.ts](../../src/lib/team/attackPlan.ts)).
3. **עיתוי מדורג:** ההתקפות מתחילות בנקודות משתנות (seed-varied), **לא כולן ביחד**; המשמרת נפתחת ב-warm-up של לוגי דמה (benign).
4. **קצב:** `load.ts` — אדפטיבי לפי מספר ה-T1 (base gap + jitter). ראה §1.5.
5. **MSEL injects:** mgmt_pressure, false_lead, vishing ticket, twist, announcements — ממוקמים יחסית ל-span, אחרי ההתקפה הראשונה.
6. **FP alerts:** התראות benign-positive עם ticket אישור ([fpAlerts.ts](../../src/lib/team/fpAlerts.ts)) — מלמדות discrimination.
7. **bonus:** מוחזק ב-`BONUS_HOLD_MS` ומשוחרר ע"י `team_release_bonus()` (0089) רק כשכל ההתקפות המתוכננות נתפסו.
8. **public/answer split:** `toPublicEntry` מפשיט מה-body את `expected_verdict/fp_explanation/incident_id/edr_scope/is_baseline` — מפתח התשובות לא דולף ל-chunks של הלקוח.

### 1.5 סקיילינג ועומס ([load.ts](../../src/lib/team/load.ts))

- קצב לוגים = `min(תקרת_חדר, קצב_לאנליסט × #T1)`, אורך משמרת 30/35/40 דק׳ (easy/medium/hard).
- מספר התקפות גדל עם גודל הצוות (stories + poolAttacks).
- אינדקסים לסקייל (0066), promote bounded (0067), feed recycling (0084).

### 1.6 מודל אבטחה

- **RLS בכל הטבלאות**; injects ו-reports וה-ops = service-only; חברים רואים רק את הסשן שלהם.
- super-admin שומר על חברות ב-`org_members` (ה-hook גוזר org_id מה-JWT) — הסתרה דרך view-exclusions.
- deny-by-default gate (0061) + security hardening (0069, 0083) + action validation (0073).
- האדמין מזין שם ארגון באנגלית → הופך ל-domain; הסביבה והמוצרים נבחרים על ידו.

### 1.7 כיסוי בדיקות (טכני)

- **32 קבצי טסט** ב-`src/lib/team` + `report/` (buildTimeline, load, attackPlan, environment, projections, iocTruth, teamXp, pauses, transition, twist, tenant, publicPayloadTells, computeReport, serverReport…).
- **סה"כ 1451 טסטים עוברים** (176 קבצים) — ראה §3.

---

## 2. מיפוי מוצרי

### 2.1 מה המוצר עושה

אימון SOC **צוותי** מרובה-משתתפים: האדמין בונה משמרת (סביבה + מוצרים + תוכנית תקיפה + הזמנת צוות לפי תפקידים), lobby גיימיפייד עם ready-check, ואז הצוות חוקר פיד חי משותף בזמן אמת — כל אחד בתפקידו — עד דו"ח ביצועים פרטני + צוותי.

### 2.2 תפקידים וקונסולות (המודל הפעיל: 4 תפקידים)

| תפקיד | קיבולת | מה רואה | פעולות עיקריות |
|---|---|---|---|
| **T1** | רב-משתתפים | פיד גולמי מלא + פילטרים/pivot | claim לוג, disposition (TP/FP/benign/suspicious), דו"ח הסלמה מובנה + IOCs, ענה ל-tickets |
| **T2** | רב-משתתפים | פיד גולמי + תור הסלמות | ack/bounce/resolve, scope.set, בקשת containment, execute isolation, EDR deep-link, דו"ח אירוע |
| **T3** | מושב יחיד | פיד + inbox + Hunt | hunt.logged, scope.confirmed, elevations |
| **SOC Manager** | מושב יחיד | **Situation Board** (מסכם, לא raw) | אישור/דחיית containment, decision log, SITREP, passdown, queue oversight |

> הבחנה חשובה: **כולם רואים את אותו פיד משותף ובאותו עיתוי**. ההבדל בין התפקידים הוא ב**תצוגה** (מנהל מקבל Situation Board מסכם במקום raw — עיצוב G-08) וב**פעולות המורשות** (gate לפי תפקיד), לא בלוגים או בתזמון.

### 2.3 מחזור החיים של המשחק

```
Builder (סביבה+מוצרים+תוכנית+הזמנה) → Lobby (presence + ready-check גיימיפייד)
  → Start (3-2-1) → Running (warm-up דמה → התקפות מדורגות + MSEL + FP)
  → bonus (אחרי תפיסת כל המתוכננות) → End → AAR + HotWash + דו"ח פרטני/צוותי
```

### 2.4 מדידה וניקוד

- **אין ציון אישי חי בזמן המשחק** (מחקרית — נחשף רק בדו"ח).
- **רובריקה פר-תפקיד** 0/4/8/12 לכל קריטריון ([computeReport.ts](../../src/lib/team/report/computeReport.ts)): T1 (triage/escalation/tickets), T2 (ack/scope/containment/incident-report), T3 (hunt/scope-confirm), Manager (approvals/decision-log/SITREP/pressure-handling).
- קריטריונים שעדיין לא ניתנים למדידה מסומנים "NOT YET MEASURED" ו**מוחרגים** מהאחוז (אין עונש על אינסטרומנטציה חסרה).
- דו"ח מחושב בשרת ([serverReport.ts](../../src/lib/team/report/serverReport.ts)) + cache ב-`team_session_reports`; MTTD מההתקפה הראשונה, decoy נחשב "טופל" רק בפעולה מפורשת.

### 2.5 סביבה וארסנל

- **8 פלטפורמות:** Azure, AWS, K8s, Linux, VMware, GitHub, CyberArk, Zeek/NDR.
- **4 ענפים:** General, Healthcare, Finance, Logistics (כל ענף מוסיף תקיפות ייחודיות).
- **~50 scenario-pack + 59 attack stories** — האדמין בוחר, הארסנל והלוגים נגזרים מהבחירה.

### 2.6 פערי UX שנסגרו (גלי G-01…G-18)

טלמטריית קליקים (dwell/MTTA), פילטרים + click-to-pivot בפיד, Shared Case מתקפל, EDR deep-link לצוות, war-room, decision log, SITREP, structured handover, escalation state-machine (bounce/resolve/elevate), help-desk injects, TI relevance + decoy IOC, incident-report grader, scope split T2↔T3, MTTC.

---

## 3. הבדיקות שבוצעו

### 3.1 שער איכות אוטומטי (ירוק לפני deploy)

| בדיקה | תוצאה |
|---|---|
| **vitest** | **1451/1451 עוברים** (176 קבצים) |
| **next build** | Compiled successfully |
| `validate:content` | PASS |
| `validate:feed` | PASS (timestamp coherence, tenant purity) |
| `validate:scenarios:integrity` | PASS (64 תרחישים, 0 errors) |
| שערי תוכן מיוחדים | investigability gate, technicalIntegrity (11 בדיקות × חברות × stacks), answer-leak check — PASS |

### 3.2 אימות בדפדפן (לאורך הפיתוח)

relay מלא T1→T2→T3→Manager עם 6 חשבונות demo; broadcast מגיע ל-2 דפדפנים Δ≈0ms; pg_cron מזרים אוטומטית; ready-check בזמן אמת; EDR deep-link; war-room round-trip; AAR תקין.

### 3.3 ביקורת מומחה (2026-10-03)

חוות דעת של מנהל SOC/IR (15 שנ') על **3 סשנים מלאים** (easy/medium/hard, סביבות שונות) + `ENV-MATRIX` + 82 storylines + `THREAT-LANDSCAPE` מאומת מול מקורות פתוחים. מסמכים: [EXPERT-OPINION](../qa/team-exercise-review/EXPERT-OPINION.md), [ENV-MATRIX](../qa/team-exercise-review/ENV-MATRIX.md), [THREAT-LANDSCAPE](../qa/team-exercise-review/THREAT-LANDSCAPE.md).

### 3.4 תיקוני ה-deploy האחרון (80b6d99)

6 ממצאי P0 + P1 מהביקורת, שתוקנו ונפרסו:
- **severity כבר לא אורקל** — הסגרה ירדה מ-~92% ל-~49%.
- **אורך שורה הושווה** — שורות תקיפה כבר לא ארוכות פי 1.7–3.3 מרעש; טקסט שורה עובדתי (fieldsOnly).
- **Windows Security כ-SIEM JSON** במקום EVTX XML + coherence guard.
- **עיתוי מדורג + warm-up דמה**; שבירות סיבתיות (twist/bonus/timestamps) תוקנו.
- **ללא קריפטו** בכל הסטורי-ליינים; אירועי סייבר מוכרים e2e.
- **ניקוד:** MTTD מההתקפה הראשונה, decoy דורש פעולה מפורשת, mgmt-pressure מדולג ללא senior.

### 3.5 QA audit מופעי (פאזות)

פאזות 1–7 בפרוד (0085/0086); פאזות 8–10 (perf, edge cases, דו"ח סופי) **נותרו**.

---

## 4. פערים פתוחים ידועים

| # | פער | חומרה | מקור |
|---|---|---|---|
| G-1 | **ריצה אמיתית ראשונה של מרובה-משתמשים בפרוד** טרם בוצעה | גבוה | memory / spec |
| G-2 | QA פאזות 8–10 (perf, edge cases, דו"ח) לא הושלמו | בינוני | QA audit |
| G-3 | `validate:logs` — **174 שדות לא מתועדים ב-registry** (קיים מראש, שדות אמיתיים, לא רץ ב-build) | בינוני | §3 deploy |
| G-4 | פריטי P2 מוצר/UX נדחו: View-as-role למדריך, החלפת תפקיד סולו, modal במקום confirm(), Ready בזמן-אמת, אזור-זמן בשעון פיד, גלילה אופקית בפיד, תפקידים במסך הזמנה | נמוך-בינוני | memory |
| G-5 | שתי משימות תוכן שנעצרו (Key Vault AuditEvent, השלמות nexacorp-chain) ב-`agents-wip.patch` | נמוך | memory |
| G-6 | רובריקות עם קריטריונים "NOT YET MEASURED" (timeline accuracy, DE FP-rate, TI) | נמוך | computeReport |
| G-7 | מדידה מול ביצוע אמיתי בעבודה (predictive validity) לא נבדקה אמפירית | מחקרי | pedagogy |

---

## 5. המלצות להמשך (מתועדפות)

### P0 — לפני מכירה כ"כלי מדידה" לארגון
1. **ריצת פיילוט חיה אמיתית** (G-1): סשן מודרך עם ≥4 משתתפים אמיתיים בפרוד, מקצה-לקצה, עם תחקור. זו הראיה היחידה שחסרה שהמנוע עומד בעומס אנושי אמיתי. **הבלוקר היחיד שנשאר לפסק הדין "מוכן".**
2. **ולידציה חוזרת של תקפות המדידה** אחרי תיקוני ה-P0: להריץ 2–3 סשנים חדשים ולמדוד מחדש את יחס ה-severity-oracle ואורך-השורה בפועל (לוודא שהתיקון תפס בשדה, לא רק בטסטים).

### P1 — איכות ואמון
3. **להשלים את ה-field registry** (G-3): 174 שדות אמיתיים חסרים ב-`scripts/log-field-registry.json`. להוסיף אותם → `validate:logs` ירוק → ניתן להוסיפו כשער CI חוסם.
4. **QA פאזות 8–10** (G-2): perf תחת עומס (50 סשנים), edge cases (ניתוקים, pause/resume, reaper), ודו"ח סופי.
5. **לסגור את ה-WIP התוכני** (G-5): Key Vault AuditEvent + השלמות nexacorp-chain — להעשיר כיסוי Azure.

### P2 — חוויית מדריך ומשתתף
6. **View-as-role למדריך** — שהמדריך יראה כל תפקיד בזמן אמת (debrief חי).
7. **מצב סולו / החלפת תפקיד** — לאפשר תרגול יחיד שעובר בין תפקידים (onboarding לפני אימון צוותי מלא).
8. **modal במקום confirm()** — ה-confirm הנייטיב נדחה אוטומטית בתצוגה מקדימה ומכוער; להחליף ב-modal אמיתי.
9. **זמן-אמת ל-Ready** + **אזור-זמן בשעון הפיד** + **גלילה אופקית מתוקנת** בפיד.

### P3 — מדידה מתקדמת ו-GTM
10. **סגירת קריטריוני "NOT YET MEASURED"** (G-6): לבנות timeline-builder ל-T2, FP-rate ל-DE — להפוך רובריקות חלקיות למלאות.
11. **Predictive validity** (G-7): לאסוף ציוני-אימון מול הערכת-מנהל בעבודה, לכייל שהציון מנבא ביצוע.
12. **אנליטיקת ארגון:** דשבורד מגמות על-פני סשנים (חוזקות/חולשות צוות לאורך זמן) — נכס מכירה ל-B2B.

### חוב טכני לתשומת לב
- **דחיפה ל-`main` חסומה** ע"י מסווג הבטיחות עד אישור מפורש בצ'אט — לתעד בתהליך ה-deploy.
- **GitHub GH013:** כל מפתח AWS מזויף חייב סיומת `...EXAMPLE`; hash 40-תווים mixed-case מסומן כסוד — lowercase. נוהל לכתיבת תוכן אימון.
- **OneDrive נועל `.next`** — ב-build תקול: `rm -rf .next` מלא (לא רק webpack/cache).
- **נתיב Hebrew OneDrive** משובש לסירוגין — לאמת עם git status אחרי כתיבה.

---

## 6. סיכום

| ממד | מצב |
|---|---|
| ארכיטקטורה | ✅ בשלה — append-only, server-authoritative, realtime-from-DB, RLS מלא |
| פונקציונליות תפקידים | ✅ 4 תפקידים עם קונסולות + gate + רובריקה |
| סביבה/ארסנל | ✅ 8 פלטפורמות × 4 ענפים, תוכנית 3+bonus, נגזר-בחירה |
| תקפות מדידה | ✅ תוקנה (P0/P1 נפרסו) — ⏳ לאמת שוב בשדה |
| בדיקות אוטומטיות | ✅ 1451 טסטים + validators + שערי תוכן |
| אימות אנושי | ⏳ ריצה חיה אמיתית ראשונה — **הבלוקר העיקרי** |
| מוכנות למכירה | 🟡 "מוכן עם תיקונים" — תיקונים בוצעו; חסרה ריצת פיילוט |

**הצעד הבא הקריטי היחיד:** פיילוט חי מודרך עם צוות אמיתי בפרוד.
