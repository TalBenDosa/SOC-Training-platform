# אבחון Team-SOC — תשתית · קישוריות · ארכיטקטורה · UX/UI · אבטחה (2026-09-26)

**שיטה:** שלושה מבקרים עצמאיים (תשתית/ארכיטקטורה/realtime · UX/UI · אבטחה) קראו את הקוד במלואו
(`team/[id]/page.tsx` ~3,460 שורות, כל ה-routes תחת `api/team/**`, מיגרציות 0049–0068, `buildTimeline.ts`,
`EventFeed.tsx`, ספריות `@supabase/*`). **כל ממצא ברמת High/Critical אומת ידנית על ידי מול הקוד**, וממצאי
ההרשאות אומתו **מול ה-DB החי של staging** (שאילתות קריאה בלבד). ממצאים חופפים בין המבקרים אוחדו.
שום קוד לא שונה במסגרת האבחון.

> **הקשר חשוב:** פיצ'ר הצוות **מעולם לא נפרס לפרודקשן** — כל הממצאים כאן חלים על staging ועל הענף
> `feat/team-soc-multiplayer-and-platform-fixes`. הם **חוסמי-עלייה-לפרוד**, לא פרצה חיה אצל לקוחות.

---

## תקציר מנהלים

הבסיס **טוב באמת**: נתיב-כתיבה יחיד (`apply_session_action`), gate של deny-by-default שמכסה את כל 30
סוגי הפעולות, זהות שנגזרת בשרת (`auth.uid()` + role מהרוסטר), RLS שמונע כתיבה ישירה, ואין SQL injection
או XSS. **אין דליפה בין ארגונים.**

הבעיות מתרכזות בארבעה צירים:
1. **אבטחה בתוך הסשן** — חבר-סשן יכול לזייף מה שחבריו רואים (broadcast), לסיים סשן לכולם, ולקרוא את
   מפתח-התשובות בזמן אמת; פונקציות מערכת פתוחות להרצה גם ל-`anon`.
2. **קישוריות** — אירוע שהוחמץ לא משוחזר לעולם (חור קבוע בלוג וב-AAR), לקוח בלובי יכול להיתקע, ושינויי
   רוסטר לא מתפשטים.
3. **תשתית** — ה-feed נעצר אחרי השהיות, ה-reaper לא יכול לנקות סשנים רצים, ומעברי-מצב לא אטומיים.
4. **ארכיטקטורה/UX** — הניקוד מחושב בדפדפן (לא סמכותי), קובץ-ענק של 3,460 שורות ללא טסטים, ו-AAR צפוף מדי.

**5 הדברים הראשונים לתקן:** (1) ביטול הרשאות `anon`/`authenticated` לפונקציות המערכת · (2) חסימת
broadcast מהלקוח · (3) הגבלת `reason` ב-end/pause · (4) הסתרת סוג ה-inject (`false lead`) מהשחקנים ·
(5) הסרת סיסמאות הדמו מה-repo הציבורי + רוטציה.

---

## 1. אבטחה

| # | חומרה | ממצא | ראיה | אימות |
|---|---|---|---|---|
| **S1** | 🔴 Critical | **כל 8 פונקציות הצוות הן `SECURITY DEFINER` וניתנות להרצה ע"י `anon` וגם `authenticated`** — כולל `promote_due_injects`, `replenish_feed`, `reap_stale_team_sessions`, `seed_session_timeline` (ללא שום בדיקת-קורא), `start_team_session`. אין אף `revoke` במיגרציות הצוות. | `0051:143`, `0056:48`, `0067:51`; `0065:172` בלי grant מפורש | **נבדק חי ב-staging:** `anon=true, authenticated=true, secdef=true` לכל ה-8 |
| **S2** | 🔴 High | **חבר-סשן יכול לשלוח broadcast מזויף לכל החדר** — מדיניות הכתיבה על `realtime.messages` מתירה `broadcast` (לא רק presence), והלקוח מקבל כל `session_event` כאמת: `session.ended` מזויף מעביר את כולם ל-AAR; `seq: 999999999` מעוור את ה-pull (שמבקש רק `seq > maxSeq`); אירועים מזויפים עם `actor_id` כלשהו נכנסים לניקוד. האפליקציה עצמה לא שולחת broadcast אף פעם — ההרשאה מיותרת. | `0050:29-34`; `page.tsx:291-300, 186, 246` | **נבדק חי:** ה-policy הפעיל מתיר `broadcast` |
| **S3** | 🟠 Medium | **כל חבר (גם observer) יכול לסיים סשן לצמיתות** עם `{"reason":"owner_left"}` — השרת לא בודק שהמדריך באמת עזב, ואין דרך לבטל סיום. ב-pause: כל `reason` שאינו `"manual"` מאפשר לכל חבר להשהות, עם טקסט `detail` חופשי שמוצג לכולם (וקטור הנדסה-חברתית). | `end/route.ts:45`; `pause/route.ts:55` | אומת בקוד |
| **S4** | 🟠 Medium (High אם הדוח משמש להערכה) | **מפתח-התשובות נשלח לדפדפן של כל שחקן בזמן המשמרת** — `expected_verdict`, `fp_explanation` בכל לוג; `expected_response`/`linked_objective` ו-`kind:"false_lead"` ב-injects. שחקן פותח DevTools ומסווג הכול נכון. | `buildTimeline.ts:122, 139-147`; `0067:36` מעתיק body מלא | אומת בקוד |
| **S5** | 🟠 Medium | **אין rate-limit על פעולות** — `message.sent`/`note.added`/`event.opened` מותרים לכל role; לולאה אחת מציפה את כל החדר, יוצרת contention על seq, ושורפת את מכסת ה-Realtime של כל הפרויקט. ה-rate-limit של ה-middleware לא חל (הקריאות הולכות ישר ל-PostgREST). | `0068:48-50`; `apply_session_action` | אומת בקוד |
| **S6** | 🟡 Low | `promote_due_injects` בלי `FOR UPDATE SKIP LOCKED` ובלי תנאי `status='pending'` ב-update → ריצות מקבילות (וגם S1 מאפשר להפעיל אותן) יוצרות **injects כפולים**. | `0067:22-45` | אומת בקוד |
| **S7** | 🟡 Low | מדיניות RLS של כתיבה ל-`team_sessions`/`team_session_members` נותנת ל-staff לעקוף את ה-routes (להוסיף משתמש מארגון אחר, להעניק `instructor`, לדלג על ready-check). ה-routes ממילא משתמשים ב-service role. | `0049:168-180, 200-201` | אומת בקוד |
| **S8** | 🟡 Low | הגישה לא פוקעת — `is_team_member` בודק רק קיום שורה; משתמש שהוסר מהארגון שומר גישת קריאה/realtime/כתיבה לסשנים ישנים. | `0049:120-126` | אומת בקוד |
| **S9** | 🟡 Low | "רואים רק את הכרטיס שלך" קוסמטי — `computeReport` מחשב ציונים של כולם בדפדפן. פרטיות-עמיתים (רלוונטי למוצר B2B למכללות). | `page.tsx:3027-3031` | אומת בקוד |
| **S10** | 🟡 Low | CSV formula injection — שם-תצוגה כמו `=HYPERLINK(...)` ירוץ באקסל של המדריך. | `page.tsx:3035-3036` | אומת בקוד |
| **S11** | 🟡 Low | **סיסמאות הדמו של staging נמצאות ב-repo ציבורי** — הוכנסו על ידי למסמך ה-TEST-SCRIPT ונדחפו. המזהה/URL/מפתחות של staging **לא** נמצאים בקבצים במעקב, כך שלא ניתן לנצל אותן לבד; הסיכון: שימוש-חוזר בסיסמה או דליפת ה-URL. | `docs/team-review/TEST-SCRIPT-…:16-17` | **נבדק:** ה-repo ציבורי (API ללא אימות → 200); ref/URL/keys לא ב-git |
| S12 | ℹ️ Info | `is_team_member` חשוף ל-`anon` (בדיקת חברות לפי UUID); זהות ה-presence נקבעת בלקוח; הודעות שגיאה גולמיות של Postgres מוחזרות; טענות JWT ישנות (~שעה אחרי הורדת-דרגה); CSP עם `unsafe-inline`/`unsafe-eval`; `npm audit`: 2 High ב-`image-size` (דרך `pptxgenjs`, route מאחורי `requireAdmin`, נגישות נמוכה). | שונות | אומת בקוד |

**בקרות אבטחה טובות (לשמר):** אימות `getUser()` בכל route · אין IDOR בין ארגונים (`sess.org_id === user.orgId`) ·
זהות ב-RPC נגזרת בשרת · gate deny-by-default מלא · אין כתיבה ישירה לטבלאות לשחקנים · `search_path` מוצמד ·
service key רק בשרת (`server-only`) · אין `dangerouslySetInnerHTML` · EDR deep-link (`?u=`) לא ניתן לניצול.

---

## 2. קישוריות (Realtime)

| # | חומרה | ממצא | ראיה | תרחיש |
|---|---|---|---|---|
| **C1** | 🔴 High | **אירוע שהוחמץ לא משוחזר לעולם.** `maxSeqRef` = ה-seq הגבוה ביותר שנראה; ה-pull מבקש רק `seq > maxSeq`; התחברות-מחדש (`SUBSCRIBED`) מסמנת "בריא" בלי pull; ה-trigger בולע כשלי broadcast בשקט; `act()` זורק את השורה שה-RPC מחזיר. | `page.tsx:186, 244-246, 304`; `0051:111-113`; `page.tsx:323` | ניתוק של שנייה מאבד seq 50, seq 51 מגיע → **seq 50 אבוד עד רענון**. לוגים/הסלמות שונים לכל לקוח, ו-AAR שונה לכל לקוח. |
| **C2** | 🟠 High | **לקוח בלובי לא מסתנכרן** — ה-pull לא רץ בלובי, הסטטוס נטען פעם אחת. מי שהחמיץ את `session.started` נתקע ב"Team lobby" בזמן שהמשמרת רצה (ועלול לגרום להשהיית-כיסוי לכל הצוות). | `page.tsx:237, 204-223` | טאב ברקע בזמן Start. |
| **C3** | 🟠 High | **שינויי רוסטר/תפקיד לא מתפשטים** — `setRoster` נקרא פעם אחת בטעינה; `/reassign` ו-`/members` לא פולטים אירוע; ה-UI אפילו כותב "Ask them to refresh". | `page.tsx:211, 1996`; `reassign/route.ts:56-60` | T2 נפל → מדריך משבץ מחליף → אצל כל השאר ה-halt לא מתבטל, המשובץ רואה קונסולה ישנה ומקבל `action_not_allowed`, והניקוד משתמש ב-rubric שגוי. |
| **C4** | 🟠 High | **"owner left" מסיים סשן בלי אפשרות לבטל, ונוטה להתרעות-שווא** — 30 שניות היעדרות presence → `/end`. אין `worker`/`heartbeatCallback` ב-client, אין טיפול ב-`visibilitychange`. | `page.tsx:478-486`; `lib/supabase/client.ts` | מדריך מחליף טאב ל-5 דק' (Chrome מאט טיימרים) → **כל הכיתה מקבלת סיום**. staff שלא ברוסטר שהתחיל את הסשן → סיום אוטומטי אחרי 30 שנ'. |
| **C5** | 🟠 Medium | **שארית באגי clock-skew** (אותה משפחה של באג הנדנוד שתיקנו): `Date.now()` מול `occurred_at` שרת ב-claim TTL (לקוח שמקדים ב-5 דק' רואה כל claim כפג → שני T1 על אותה התראה), guiding nudge, SLA/orphan בתור T1, עדיפות T2, עומס ב-Situation Board. | `page.tsx:525, 569, 1122, 1098-1102, 1450-1456, 3290-3307` | תלוי בשעון של כל מחשב. |
| C6 | 🟡 Medium | אין אינדיקציית חיבור — הכותרת תמיד "Live" גם כשהערוץ נפל; שגיאות pull נבלעות; שגיאות `act` גולמיות ו"דביקות"; polling fallback קבוע 10 שנ' בלי backoff/jitter (עומס סינכרוני בדיוק בזמן תקלה). | `page.tsx:764, 246, 324, 257-259` | — |
| C7 | 🟡 Low | ה-auto-pause על כיסוי: debounce של 12 שנ' להשהיה אבל חידוש מיידי → churn ברשת מהבהבת; שני לקוחות "נבחרים" יכולים להילחם. | `page.tsx:399-408, 443` | — |

---

## 3. תשתית ו-DB

| # | חומרה | ממצא | ראיה |
|---|---|---|---|
| **I1** | 🟠 High | **`replenish_feed` מתעלם מ-`paused_ms`** → אחרי השהיה מצטברת של 10 דק' ה-feed מספק 6 אירועים ואז שותק ~10 דק' שוב ושוב. השהיות-כיסוי אוטומטיות הופכות את זה לנפוץ. **תיקון בשורה אחת.** | `0056:24` (ההגדרה היחידה — אומת) |
| **I2** | 🟠 Medium | **ה-reaper לא יכול לנקות סשן רץ** — תנאי ה-idle דורש שאין injects ב-`pending`, אבל `replenish_feed` שומר ≥4 pending לנצח; ו-`'skipped'` לא נקבע בשום מקום. סשן נטוש ממשיך לקדם/לשדר עד תקרת 4 שעות; סשנים שהסתיימו מחזיקים pending לנצח (האינדקס החלקי "הקטן" גדל). | `0066:52-57`; `0056:20`; `'skipped'` רק ב-check constraint (אומת) |
| **I3** | 🟠 Medium | **מעברי-מצב לא אטומיים** — `end`/`start`/`pause` מעדכנים סטטוס ואז מוסיפים אירוע בנפרד; כשל ב-append = סטטוס בלי broadcast; כשל ב-seed = סשן `running` בלי injects שאי אפשר להתחיל מחדש. `/start` מקבל גם `paused` ומאפס `started_at`. | `end/route.ts:50-52`; `start/route.ts:29, 40-59`; `pause/route.ts:83-89` |
| I4 | 🟡 Medium | tick ה-promote: predicate שהאינדקס לא יכול לסרוק (ביטוי עם cast לטקסט) → כל pending של כל סשן נבדק כל 5 שנ'; אצווה של 500 בטרנזקציה אחת (כשל אחד מפיל את כולם); 4 עותקים של לולאת `max(seq)+1`; `session_state` נכתב ולא נקרא אף פעם; `occurred_at = now()` (זמן תחילת טרנזקציה) → סדר-זמנים הפוך מ-seq ב-HandoffLadder. | `0067:22-45`, `0049:81` |
| I5 | 🟡 Medium | telemetry קליקים (`event.opened`) = RPC + broadcast על כל פתיחה/סגירה → ב-50 שחקנים ~250 הודעות/שנ' מזה בלבד; מפיל את ה-`memo` ומרנדר את כל החדר כמה פעמים בשנייה; ~20 `useMemo([events])` O(n) + מיון מלא על כל הודעה. | `EventFeed.tsx:941-951`; `page.tsx:187, 493-575, 811` |
| I6 | 🟡 Medium | RLS על `session_events` קורא לפונקציה לכל שורה (`auth.uid()` לא עטוף ב-`(select …)`). | `0049:185` |
| I7 | 🟡 Medium | `cron.job_run_details` גדל ללא הגבלה (~26K שורות/יום, אין purge). | `0052:22`, `0056:52`, `0065:205` |
| I8 | ⚪ Low | idempotency key חסר-ערך (`type-uid-Date.now()` → לחיצה כפולה = 2 אירועים) · אין תקרת רוסטר ב-`/members` (`max_size` לא נאכף) · pull עוצר ב-30K אירועים · snapshot מלא של לוג בכל הסלמה (סיכון `payload_too_large`) · `/end`/`/pause` לא נכנסים ל-audit. | שונות |

---

## 4. ארכיטקטורה

| # | חומרה | ממצא |
|---|---|---|
| **A1** | 🟠 High | **הניקוד מחושב בדפדפן** (`computeReport` ב-`page.tsx:3027`) — לא סמכותי: שני לקוחות עם חורים שונים (C1) או רוסטר שונה (C3) מציגים AAR שונה; ה-CSV מייצא את מה שהדפדפן הזה חישב; ומחייב שליחת מפתח-התשובות לדפדפן (S4). |
| **A2** | 🟠 Medium | **קובץ אחד של ~3,460 שורות** מחזיק את כל החדר (15-props drilling, `page.tsx:838`) · **אפס טסטים לקוד הצוות** (14 קבצי vitest, אף אחד לא נוגע ב-team). |
| **A3** | 🟡 Medium | **שחזור claims/עומס משוכפל 4 פעמים עם כללים שונים** (`page.tsx:554-563`, `1109-1124`, `3295-3305`, ו-`computeReport` **בלי TTL**) → ה-AAR מעניש מנהל על עומס שלא הוצג לו. גם לוגיקת ה-lifecycle כתובה פעמיים (`296-299` ו-`449-464`). |

**תוכנית פיצול מוצעת:**
- `src/lib/team/` (טהור, isomorphic, נבדק ב-vitest): `types.ts` · `eventLog.ts` (merge + watermark רציף + זיהוי-חורים) ·
  `lifecycle.ts` · `projections.ts` (claims/load אחד, מכונת-מצבי הסלמה) · `report/` (computeReport, rubrics,
  handoffLadder, hotwash) · `clock.ts` (`serverNow()`).
- Hooks: `useTeamSession` · `useSessionEvents` · `useTeamRealtime` · `useTeamActions`.
- קומפוננטות: `lobby/`, `room/`, `consoles/*`, `shared/*`, `report/*` + `TeamRoomContext`.
- טסטים: fixtures ל-computeReport (self-correction, contested, curveballs, backup), `reconstructClaims` עם TTL,
  `deriveLifecycle`, זיהוי-חורים ב-merge, דטרמיניזם של `buildTeamTimeline`, ומטריצת SQL ל-`session_action_allowed`.

---

## 5. UX/UI

| # | חומרה | ממצא | ראיה |
|---|---|---|---|
| **U1** | 🔴 High | **דליפת "no-hints" — ה-inject מכריז על עצמו.** `InjectFeed` מציג לכל שחקן את `kind` הגולמי: decoy מופיע עם התג **"false lead"**, ו-twist עם **"twist"**. זה מבטל את מנגנון ה-P2 (שאני הוספתי). | `page.tsx:2069-2073` (אומת) |
| **U2** | 🟠 High | **ה-AAR נפתח בקיר של 16 אריחים** ללא קיבוץ, ועם ראשי-תיבות ללא הסבר (MTTD/MTTC/MTTR זה לצד זה) — ברגע הכי עמוס-קוגניטיבית. | `page.tsx:3050-3067, 3161-3163` |
| **U3** | 🟠 High | כותרת ה-Topbar נשארת **"Team lobby"** במסך ה-AAR (אין ענף ל-`ended`). | `page.tsx:628` (אומת) |
| **U4** | 🟠 High | מדריך-התפקיד מבטיח UI שלא קיים בשם הזה ("End exercise" / "after-action report" מול "End session" / "Shift review"). | `page.tsx:73` |
| U5 | 🟡 Medium | בונה הסשן מזהיר רק על T1 חסר, לא על T2 — אפשר ליצור סשן שיעצור מיד על כיסוי. | `team/page.tsx:168-172` |
| U6 | 🟡 Medium | באנר הנדנוד **מציג בשם** את האנליסט העמוס לכל החדר — בסתירה להבטחת ה-no-fault. עדיף ניסוח ממוקד-משימה ("תור ה-T1 מצטבר — אם פנוי, קח את הבא"). | `page.tsx:685-690` |
| U7 | 🟡 Medium | שורות סשן סגור נראות לחיצות אבל אינן (רק tooltip) — מודל אינטראקציה משתנה בין שורות. | `team/page.tsx:217-219` |
| U8 | ⚪ Low | נגישות: ~45 מופעים של טקסט 9–10px ב-`slate-500/600` על רקע כמעט-שחור (על גבול WCAG AA, חלק מתחת) — כולל טיימרי SLA · כפתורי X בלי `aria-label` (4 מקומות, כולל באנר הנדנוד) · `<button>` ידניים בלי focus ring · מצב שמקודד בצבע בלבד. | `page.tsx:634, 651, 688, 1365` ועוד |
| U9 | ⚪ Low | ~20 עותקים של מחלקות badge (אין `<SeverityBadge>` משותף) · "Take next" בלי אישור ויזואלי · ה-Manager עם `is_staff` רואה feed גולמי במקום Situation Board. | שונות |

**עובד טוב (לשמר):** lifecycle עם auto-pause/owner-left ו-overlay ברור · `rowStatus` ב-feed הוא מימוש מופתי של
no-hints · צ'קליסט איכות ההסלמה החי · נראות בעלות עקבית בכל הטירים (🔒 claimed / being worked / ⚠ unclaimed) ·
Handoff Ladder ו-Hot-wash חזקים פדגוגית.

---

## 6. מפת-דרכים מתועדפת

### שלב 0 — דחוף, לפני כל דבר אחר (שעות)
1. **S11** — הסרת סיסמאות הדמו מהמסמך + commit; **רוטציה** של סיסמאות הדמו ב-staging (ההיסטוריה ב-git נשארת).
2. **S1 + S6** — מיגרציה 0069: `revoke execute … from public, anon, authenticated` לפונקציות המערכת; `drop` ל-`seed_session_timeline` ו-`start_team_session`; `revoke` ל-`anon` על `apply_session_action`/`is_team_member`/`is_session_staff`; `FOR UPDATE SKIP LOCKED` + `and status='pending'` ב-promote. אימות עם `has_function_privilege`.
3. **S2** — מדיניות הכתיבה ב-`realtime.messages` → `extension = 'presence'` בלבד; בלקוח — דחיית seq שקופץ יותר מ-~1000 מעל הראש.
4. **S3** — whitelist ל-`reason` (pause: `manual|coverage`, end: `manual|owner_left`), החרגת observer, `owner_left` → **השהיה** במקום סיום, בלי `detail` חופשי ממשתמשים לא-מורשים.
5. **U1** — `InjectFeed` מציג תג ניטרלי ("update"/"ticket") ל-`twist`/`false_lead`/`mgmt_pressure`.

### שלב 1 — ימים
6. **C1** — watermark רציף + pull מיידי כשיש קפיצה ב-seq + pull על כל `SUBSCRIBED` ו-`visibilitychange` + מיזוג השורה שה-RPC מחזיר.
7. **C2** — סנכרון סטטוס בלובי. **C3** — אירועי `member.added`/`member.role_changed` + רענון רוסטר ו-`me`.
8. **I1** — `- s.paused_ms` ב-`replenish_feed` (שורה אחת). **I2** — סימון injects כ-`skipped` בסיום/reap; idle לפי פעילות actor.
9. **C4 חלקי** — `realtime: { worker: true, heartbeatCallback }`; policy קריאה ל-staff.
10. **C5** — `useServerClock()` + טיק של 15 שנ' ל-SLA.
11. **S5** — rate-limit לכל משתמש/סשן בתוך `apply_session_action`.
12. **UX quick wins** — U3, U4, U5, U6, aria-labels (U8), והגבלת `event.opened` מ-broadcast (I5).
13. **I7** — purge יומי ל-`cron.job_run_details`. **S10** — prefix ל-CSV.

### שלב 2 — מבני (1–3 שבועות)
14. **ניקוד סמכותי בשרת (A1 + S4 + S9)** — הוצאת ground-truth מה-payloads, חישוב ה-AAR בשרת בסיום ושמירתו (`grade.assigned`), והחזרת הכרטיס של המשתמש בלבד. סוגר שלושה ממצאים יחד.
15. **presence בצד השרת** — heartbeat RPC ל-`last_seen_at` + cron שמחליט על כיסוי/היעדרות-מדריך עם hysteresis. מסיר split-brain, עקיפת `owner_left`, וסיומי-שווא מטאב ברקע.
16. **RPCs אטומיים למעברי-מצב + מקצה-seq יחיד** (I3, I4) — מבטל 4 לולאות retry ואת `session_state`.
17. **פיצול `page.tsx` + טסטים** (A2, A3) לפי התוכנית בסעיף 4.
18. **U2** — ארגון ה-AAR: Hot-wash קודם, מדדים מקובצים (Detection/Response/Resolution/Coordination) עם מקרא, השאר ב-disclosure.
19. **Observability** — טבלת כשלי-broadcast במקום בליעה שקטה, view של `team_ops_health` (promote lag), והתראות.
20. **S7/S8** — ביטול מדיניות כתיבה מצד-לקוח; `is_team_member` מחייב חברות ארגון פעילה; route להסרת חבר.

---

## 7. סטטוס ביצוע (עודכן 2026-09-26)

כל הפריטים בוצעו על הענף `feat/team-soc-multiplayer-and-platform-fixes` ומיגרציות 0069 + 0071 + 0072 הוחלו על
**staging בלבד** (0071 אומתה בכ-40 בדיקות SQL על סשני-בדיקה). **לא נפרס לפרודקשן.**
commits: `4797c43` (שלב 0) · `d3fbdca` (פיצול + computeReport) · `ec9ae61` (שרת/DB) · `dba3012` (לקוח) · תיקוני סקירה עצמאית (0072).

**סקירה עצמאית אחרי הביצוע** מצאה 7 ממצאים — כולם תוקנו ואומתו על staging: (1) קריטי — סשן חדש הושהה
~80 שנ׳ אחרי Start כי הלקוחות בלובי לא ידעו שהוא v2 ולא שלחו heartbeat; (2) הוגנות ה-jobs מעל 50 סשנים;
(3) דליפת תאריכים — לוגי התקיפה זוהו לפי התאריך המקורי שלהם; (4) חבר שהוסר חסם Start; (5) הגנת
הלחיצה-הכפולה בלעה פעולות הפוכות; (6) Start כפול זרע את ה-feed פעמיים; (7) מנהל עם שיוך שפג יכל
לסיים/להשהות דרך ה-API.

**גידור גרסאות:** `team_sessions.schema_version` — סשן שנפתח מעכשיו (`/start`) הוא v2 ומקבל את כל ההתנהגות
החדשה (presence בשרת, מפתח-תשובות מחוץ לרשת, קליקים מחוץ ללוג). סשנים קיימים (v1) ממשיכים כמו קודם, כך
שהחלת ה-DB לפני הלקוח לא שוברת סשן רץ.

| פריט | סטטוס | איך נסגר |
|---|---|---|
| S1, S6 | ✅ | 0069: revoke לכל פונקציות המערכת, drop ל-seed/start הישנות, `SKIP LOCKED` ב-promote. 0071: כל אובייקט חדש revoked (רק `team_heartbeat` ל-authenticated) |
| S2 | ✅ | 0069: כתיבה ל-`realtime.messages` = presence בלבד |
| S3 | ✅ | whitelist ל-reason; ב-v2 רק staff/מנהל פעיל יכולים להשהות/לסיים; `owner_left`/`coverage` נקבעים ע"י השרת בלבד |
| S4, U1 | ✅ | מפתח-התשובות ב-`session_injects.expected_action` (staff בלבד); body ציבורי בלי `expected_verdict/fp_explanation/incident_id/edr_scope/is_baseline`, `tier` אחיד, מזהים אטומים; סוג ה-inject מוצג כ-"update" |
| S5 | ✅ | token bucket ב-`apply_session_action` (~60/דק', burst 30, replays פטורים) + תקרת 20K אירועים לשחקנים |
| S7, S8 | ✅ | מדיניות כתיבה מהלקוח הוסרו; `is_team_member` מחריג `left` ודורש חברות ארגון פעילה; `DELETE /members` להסרת חבר |
| S9, A1 | ✅ | `GET /report` מחשב פעם אחת בשרת, שומר ב-`team_session_reports`, ומחזיר כרטיס אישי בלבד (staff/מנהל רואים הכול) |
| S10 | ✅ | CSV עם הגנת-נוסחאות, ורק ל-staff |
| S11 | ⚠️ חלקי | הסיסמאות הוסרו מהמסמך; **הרוטציה ב-staging עליך** (ההיסטוריה ב-git נשארת) |
| S12 | ✅ | הודעות שגיאה גנריות בכל ה-routes; `is_team_member` ל-anon בוטל (0069). CSP ו-`image-size` מחוץ להיקף |
| C1, C2 | ✅ | watermark רציף + gap-fill; pull בכל שלב (גם לובי), ב-`SUBSCRIBED`, ב-visibility ובזיהוי חור; מיזוג השורה מה-RPC |
| C3 | ✅ | אירועי `member.added/role_changed/removed` → רענון רוסטר ו-`me` |
| C4, C7 | ✅ | presence בשרת: `team_heartbeat` כל 15 שנ' (גם מ-`/edr`) + `team_lifecycle_tick` כל 10 שנ' עם hysteresis; היעדרות מדריך = **השהיה** (לא סיום). אין יותר "בחירת" לקוח |
| C5 | ✅ | `serverNow()` מכויל מכותרת `Date` + טיק 15 שנ' ב-claim TTL / SLA / עומס / oldest-unacked |
| C6 | ✅ | תג Live/Reconnecting, backoff+jitter, שגיאות ידידותיות שמתנקות |
| I1, I2, I3, I4 | ✅ | `replenish_feed` מחסיר `paused_ms` ומסנן `channel='feed'`; `team_transition` אטומי (end ⇒ `skipped`); allocator יחיד + נעילה-ראשונה; `occurred_at = clock_timestamp()`; reaper לפי פעילות actor + heartbeat |
| I5 | ✅ | ב-v2 קליקים נכתבים ל-`session_clicks` (בלי seq ובלי broadcast) |
| I6 | ✅ | RLS מבוסס-סט (`team_my_sessions()`/`team_staff_sessions()`) |
| I7 | ✅ | purge יומי ל-`cron.job_run_details` |
| I8 | ✅ | idempotency key = type+hash(payload)+חלון 2 שנ'; תקרת רוסטר 60; קיטוע snapshot מעל 8K; audit ל-end/pause |
| A2 | ✅ | page.tsx פוצל ל-`_components/*`; 39 טסטים לקוד הצוות (characterization, projections, buildTimeline, serverReport) |
| A3 | ✅ | `lib/team/projections` = כלל claims/עומס אחד, כולל שחזור ב-AAR לפי זמן-אירוע |
| U2, U3 | ✅ | AAR: 4 מדדי-כותרת + מקרא, "Show all metrics" מקובץ; כותרת "Shift review" |
| U4–U7 | ✅ | תיקון טקסטים במדריך; אזהרת Tier-2 חסר; נדנוד בלי שם; שורה סגורה כולה לינק ל-Shift review |
| U8 | ✅ | aria-labels לכפתורי X, focus-visible, ניגודיות בתוויות |
| U9 | ✅ חלקי | אישור ויזואלי ל-Take next; מנהל עם הרשאות staff רואה Situation Board. רכיב `<SeverityBadge>` משותף — לא בוצע (קוסמטי) |
| Observability (19) | ✅ | `team_ops_events` + view `team_ops_health` (לשירות בלבד) |

**נשאר ידני:** הרצה חיה של שני משתמשים לפי ה-TEST-SCRIPT (האימות מכאן לא אמין ב-staging), ורוטציית סיסמאות הדמו.

---

*נספח: הדוחות המלאים של שלושת המבקרים (עם כל ה-`file:line`) שמורים בתמליל הסשן; כל ממצא מסומן כאן עם הראיה המרכזית.*
