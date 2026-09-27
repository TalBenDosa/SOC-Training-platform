# mgr — SOC Manager / Shift Lead — חוות דעת

## ציונים (1–5): ריאליזם מקצועי | חוויית משתמש | יציבות/תקינות | שיתוף פעולה | הוגנות הניקוד
**4 | 3 | 3 | 4 | 3**

- **ריאליזם מקצועי 4**: סט ה-injects (CISO, Legal, Exec, כרטיס vishing, false lead, twist, תרגיל כיסוי) ריאלי מאוד, ובקשת ה-containment נושאת criticality/blast radius/business owner, כך שאישור או דחייה הם trade-off אמיתי. הורדתי נקודה כי תיק משותף אחד מחזיק שלושה אירועים נפרדים, ובגלל ה-target הנעול (פירוט בהמשך).
- **חוויית משתמש 3**: ה-Situation Board מספיק כדי לפקד בלי לוגים גולמיים, אבל חסרים בו owner לכל תיק ומצבי resolved/bounced. בנוסף, "Oldest unacked" מציג אזהרת שווא קבועה.
- **יציבות 3**: לא הייתה אף קריסה או stack trace. pause, auto-pause ו-auto-resume עבדו. מנגד, השרת קיבל כמה payloads שבורים (escalation ריק, `event_id:"undefined"`, תשובה כפולה לכרטיס).
- **שיתוף פעולה 4**: זרימת T1→T2→Mgr→T2 execute עבדה מהר (MTTA≈0.5 דק', approval≈0.5 דק'). הרבה מהתיאום עבר בצ'אט חופשי במקום באובייקטים מובנים.
- **הוגנות 3**: הכרטיס שלי (94%) הוגן בערך. בכרטיסים של אחרים יש באגים ברורים בניקוד: Help-desk מנוקד לפי ספירה, TI מקבל 100% על 2 שורות מתוך 5, ו-T1 שמסמן מהר בלי לפתוח לוגים מתוגמל על המהירות.

## מה עשיתי במשמרת (ציר זמן קצר: seq + פעולה + למה)
| seq | שעה | פעולה | למה |
|---|---|---|---|
| 3 | lobby | `ready mgr` | אחרי קריאת SituationBoard/LeadConsole/MgrConsole/SitrepConsole/DecisionLog/SharedCase/projections |
| 22 | 08:01 | הודעת פתיחה: חלוקת lanes, כללי containment (T2 מגיש דוח → בקשה → Mgr מאשר → T2 מבצע) | להגדיר separation of duties מראש |
| 39 | 08:02 | `case.assigned` → T2 | הסלמה ראשונה נכנסה, לתיק צריך owner (Team organised) |
| 89/91 | 08:04 | `containment.approved` r.williams + `decision.logged` | דוח TP קיים, exfil פעיל ל-proton.me, blast radius של משתמש אחד |
| 129 | 08:07 | הנחיה ל-t1b להסלים את story B (WS-OPS-2214) | T3 ו-TI זיהו שרשרת, אבל לא היה כרטיס בתור |
| 147 | 08:07 | **SITREP #1 (CISO)**, 21 שניות אחרי ה-inject | "contained or spreading?": A contained, B investigating |
| 172 | 08:08 | הנחיה אחרי ה-escalation הריק #146, וסימון #144 (p.wright DA) כעדיפות | בקרת איכות על התור |
| — | 08:10 | ניסיון `coordination.nudge` ל-T2 (load=3) → **REJECTED: status paused** | ה-instructor השהה ידנית בדיוק בזמן עומס היתר |
| 213/216 | 08:11 | אישור בידוד WS-OPS-2214 + decision | ביצוע loader מאומת ב-EDR |
| 236 | 08:12 | תגובה ל-false lead של Marketing SaaS: לאמת מול רשימת ספקים מאושרים, לא לחסום | discrimination, לא over-reaction |
| 268 | 08:14 | `coordination.nudge` ל-t1b (5 claims) | batch-claiming מסתיר עבודה |
| 277 | 08:14 | הנחיה לכרטיס ה-vishing: לסרב ולהסלים, וקישור ל-story A | |
| 316 | 08:16 | **SITREP #2 (Legal)**, 28 שניות אחרי ה-inject | A עשוי לחייב דיווח (דואר Compliance הועבר החוצה); B ללא חשיפת מידע |
| 340/346 | 08:18 | `case.status_set investigating/high` + decision: "containment A נכשל" | VPN מוצלח מלונדון אחרי החסימה + twist ה-EDR |
| 384 | 08:19 | nudge ל-T2 (3 תיקים) | |
| 405/407 | 08:21 | **`containment.denied`** ל-story C + decision שמאשר containment של זהות | ה-target ננעל על WS-FIN-2847 (התחנה של j.chen, נכס שגוי) |
| 415/417 | 08:21 | אישור re-containment ל-r.williams (VPN kill, AD disable, MFA wipe) | |
| 462/464/466 | 08:23 | אישור בידוד WS-ENG-2093 (crown jewel) + decision + nudge חוזר ל-T2 (5 תיקים) | Domain Admin זדוני חי עם SeDebug |
| 483 | 08:23 | **SITREP #3 (Exec bottom line)** | |
| 501 | 08:24 | דחיפה ל-DLP d.brown שלא קיבל ack | הפריט היחיד שיכול לשנות את התשובה ל-Legal |
| 587/588/591 | 08:29 | nudge ל-T3 (3), `handover.noted` מובנה, סטטוס התיק → contained | סוף משמרת |

## מה עבד טוב
- **ה-Situation Board מספיק לפיקוד**: MTTA, Oldest unacked, `N open` לאנליסט, תור הסלמות וספירות חומרה. לא נזקקתי ללוג גולמי אחד במשך כל המשמרת.
- **כרטיס האישור (LeadConsole.tsx:73-79)** מציג את ה-determination וה-recommendation של T2 ואת ה-scope, ומזהיר כשחסר דוח. זה מונע אישור עיוור, וזו separation of duties נכונה: T2 מבקש, Mgr מאשר או דוחה עם נימוק (חובה בדחייה), T2 מבצע.
- **Injects**: שלוש דרישות ניהוליות שונות באמת, כל אחת עם קהל ומטרה משלה (CISO: מצב, Legal: חשיפה ודיווח, Exec: שורה תחתונה). ה-twist של re-scope והכרטיס של vishing משתלבים בסיפור.
- **תרגיל הכיסוי**: auto-pause ב-08:26:41 ו-auto-resume ב-08:28:01 בלי אובדן state. T2 דיווח ש-resolve בזמן pause נדחה כמצופה.
- **הקרנת העומס** (`projections.ts`) זהה בין הלוח ל-AAR. שחזרתי אותה ידנית והתוצאות תאמו.

## תקלות / שגיאות מערכת (כל אחת: חומרה, שחזור מדויק, פלט שקיבלת)
1. **בינונית-גבוהה: השרת מקבל `escalation.requested` עם payload ריק.** seq 146 (t1b), `escalation.requested {}`, התקבל בלי event_id, summary או IOCs. שער האיכות קיים רק בקליינט. אחר כך T2 עשה bounce עם `"event_id":"undefined"` (seq 164) וגם זה התקבל. באותו אופן התקבל `disposition.set {"verdict":"benign"}` בלי event_id (seq 25).
2. **בינונית: הסלמה שעברה bounce נשארת "open" לנצח בלוח.** `SituationBoard.tsx:28,43-44,126` מחשב ack/open רק מ-`escalation.acknowledged`. #146 ו-#217 עברו bounce אבל נשארו OPEN, ולכן "Oldest unacked" הציג כ-16+ דקות וטון warn מ-T+13 ועד הסוף, כלומר אזהרת שווא קבועה למנהל. אותו באג קיים ב-`LeadConsole.tsx:26-27` (Queue oversight מבקש "לרדוף" אחרי כרטיס שעבר bounce).
3. **בינונית: הסלמות כפולות על אותו event_id מתקבלות.** #357 שוכפל על efef2ac740d53 אחרי #351, ו-#261 נשלח על e88ed758451ff שכבר היה resolved. T2: "I cannot bounce it". בלוח הכפילות מופיעה כשורה נוספת עם "ack".
4. **נמוכה-בינונית: תשובה כפולה לכרטיס help-desk מתקבלת** (seq 299 t1a, seq 319 t1b), ושני האנליסטים מקבלים קרדיט.
5. **נמוכה: claim שני דורס claim קיים בשקט** (דיווח t1b ב-seq 361, ‏#341/#344 בהפרש 5 שניות). התוצאה הייתה עבודה כפולה על #318.
6. **נמוכה (סמנטיקה נכונה, השפעה לא הוגנת): `coordination.nudge` נדחה בזמן pause.** `REJECTED: action_not_allowed: coordination.nudge for role mgr in status paused`. עומס היתר של T2 (08:09:27 עד 08:11:18) חפף כמעט כולו ל-pause הידני (08:10:12 עד 08:11:05). ה-replay ב-`computeReport.ts:221-248` לא מדלג על חלונות pause.
7. **בעלות על תיק לא נאכפת**: T2 עשה ack ל-eef6d3d2bbe48 אחרי ש-T3 כבר לקח אותו (seq 84), ואחר כך סגר אותו (seq 211) בזמן שה-owner לפי ההקרנה הוא T3.
- מלבד אלה לא היו שגיאות. (EPIPE שראיתי נגרם מ-`| head` שלי, לא מהמערכת.)

## שגיאות מקצועיות בתוכן (לוג/שדה/ורדיקט/MITRE/תרחיש — עם feed id וציטוט השדה)
(לא חקרתי raw בעצמי, לפי משמעת המושב. הממצאים באים מדוחות הצוות ומשורות ה-feed ברמת התיאור, ואומתו בסוף המשמרת.)
1. **ef3f29b239296 (#291, 4720) ו-efef2ac740d53 (#318, 4728)**: אירועים על חשבון דומיין נרשמו על תחנת עבודה: `host=WS-FIN-2847`, "created the domain user s.katz on WS-FIN-2847". 4720/4728 לחשבון דומיין נכתבים על ה-DC. **ההשלכה המבצעית:** ה-hostname הזה נכנס ל-target של בקשת ה-containment, והביא לבקשה לבודד את התחנה של j.chen, שנדחתה על ידי (seq 405).
2. **efae5da358c0c (#131, MDE FileCreated)**: `file.path` המפוענח מציין `C:/Users/d.rosen/Downloads` בעוד שה-raw ‏(וה-description) מציינים d.morgan (T3 seq 157, דוח T2 seq 189).
3. **ef4f29cb6658b (#305, Purview DLP)**: ה-description אומר "d.brown **copied** 3,200 employee PII records", אבל ב-raw מופיע `purview.action block, action_result blocked` (T3 seq 516). הסתירה נוגעת ישירות לשאלת החובה לדווח ל-Legal.
4. **Twist inject "host… now beaconing to a NEW C2"** (seq 335): אין אף שורת telemetry שתומכת בו. T3 (seq 505) ו-TI (seq 513) סרקו ולא מצאו. inject כזה צריך להגיע עם לוג EDR או DNS שאפשר לאמת.
5. **שעונים לא עקביים**: ה-ts של ה-feed הוא 08:xx (עם תאריך 2026-01-01), התיאורים מציינים "13:45:44", "At 22:51" ו-"20:29", ה-CHG window הוא 05/10-05/11, וכותרות הדואר מאמצע יוני (TI seq 169). זה מקשה לבנות timeline, שהוא בדיוק הבסיס ל-SITREP ולהחלטת דיווח.
6. **efff2ae073a78 (#312)**: `sev=informational` על VPN מוצלח של החשבון שהוכל, 10 דקות אחרי containment, כלומר ה-twist המרכזי של story A. בנוסף, t1b/T2 הראו ש-82.102.14.x הוא egress של gateway הלונדוני של הארגון עצמו (seq 597). זה מחליש את הסיפור ויוצר עמימות אם זה re-compromise או משתמש לגיטימי.

## חיכוך בחוויית המשתמש (עם file:line מהקומפוננטה)
1. **target נעול ב-containment**: `T2Console.tsx:103`, ‏`target = p.entity || p.hostname || …`, בלי אפשרות עריכה. אי אפשר לבקש containment לחשבון (s.katz/m.torres) או לנכס אחר (WS-ENG-2208). ב-`LeadConsole.tsx:83-84` יש רק Approve או Deny לכל הבקשה, בלי "approve with modified scope". נאלצתי לדחות ולאשר containment של זהות מחוץ למערכת דרך Decision log, כך שהפעולות האלה לא נרשמו כ-containment.executed.
2. **תיק משותף יחיד לשלושה אירועים**: `SharedCase.tsx:125-156` מחזיק status, severity ו-owner אחד. בפועל היו A (BEC), B (drive-by) ו-C (DA backdoor) עם מצבים שונים. בסוף נאלצתי לסמן "contained" לתיק שבו C עוד לא הושלם.
3. **בתור ההסלמות בלוח אין owner, גיל או resolved**: `SituationBoard.tsx:117-127` מציג רק what/host/actor/ack-open. למנהל חשוב לדעת מי מחזיק כל תיק ומה נסגר, ועכשיו זה מופיע רק כמספר מצטבר ("N open") לאנליסט.
4. **ל-SITREP אין שדה קהל** (CISO/Legal/Exec): `SitrepConsole.tsx:202`. כתבתי את הקהל בתוך הטקסט. גם ברשימה (שורות 210-214) מוצגים רק situation ו-status.
5. **"Shift management" סופר פעולות** (`MgrConsole.tsx:149-152`): t1b עם 86 dispositions נראה "הכי פעיל", למרות שפתח רק 12 לוגים (avgDwell 7s). זה מדד עומס מטעה ליד מדד ה-open-load הנכון.
6. **כרטיס Rebalance בזמן pause** (`SituationBoard.tsx:98-111`) ממשיך להציג כפתור Nudge שייכשל, בלי הודעה ברורה.
7. **אין hysteresis לעומס**: ‏t1a היה "overloaded" במשך 29 שניות (08:16:38 עד 08:17:07, בזמן שסימן שתי התראות ברצף), וזה נספר כעומס שלא טופל.

## הדוח שלי (Shift review) — האם הוגן? מה חסר/שגוי?
**הכרטיס שלי: 94%.** Team organised 12, Time-to-approval 12, Decision log 12, Cadence+SITREP 12, **Load balancing 8**, Management pressure 12.
- **הוגן**: ‏owner שובץ תוך דקתיים. זמן האישור היה כחצי דקה (3 אישורים). 6 החלטות, כולן עם נימוק. 3 SITREPs שהותאמו אחד-לאחד ל-3 ה-mgmt injects. זה תואם למה שעשיתי.
- **Load balancing 8**: לפי ה-replay שלי, 4 אנליסטים הגיעו לעומס יתר (T2, t1b, t1a, T3) ועשיתי nudge ל-3 מהם. ה-miss הוא t1a ב-29 השניות. לפי הכלל זה נכון, אבל מקצועית מנהל לא מתערב על blip של חצי דקה, כך שהמנגנון צריך סף משך. מצד שני, ה-nudge הראשון שלי ל-T2 נדחה בגלל pause, ובכל זאת T2 נחשב "מטופל" בזכות nudge מאוחר יותר ב-08:19. כלומר המדד בודק "האם אי פעם", ולא זמן תגובה.
- **חסר ברובריקה**: (א) **איכות ה-SITREP לא נמדדת**. נספרת רק כמות, וכל SITREP של 8 מילים באותו חלון היה מקבל 12. (ב) **דחייה נכונה (wrong asset) לא מתוגמלת**, למרות שזו הפעולה המקצועית החשובה ביותר שעשיתי כמנהל. Time-to-approval מחשב רק approved. (ג) בקשה פתוחה בסוף (seq 602, ‏5 שניות לפני end) לא נספרת. זה בסדר, אבל עדיף לציין אותה כ"pending".
- **הוגנות כרטיסי הצוות** (אני רואה את כולם):
  - **Help-desk tickets** (`computeReport.ts:114`) מנוקד לפי **כמות** (3 כרטיסים = 12), אבל במשמרת הוזרק כרטיס אחד. לכן ציון 4 הוא המקסימום האפשרי, ושני ה-T1 קיבלו 4 על אותו כרטיס. גם נכונות ההחלטה (Handle מול Refuse) לא נבדקת. זה באג ברור.
  - **t1b 59% מול t1a 58%**: ‏t1b עשה 86 dispositions ופתח 12 לוגים (avgDwell 7s), ו-t1a פתח 27 (avgDwell 31s). t1b קיבל Disposition accuracy 8 מול 4, ואין שום קנס על סימון בלי פתיחה. הרובריקה מתגמלת rubber-stamping.
  - **t1a Escalation precision 0** למרות שהסלים את ה-lure, את ה-inbox rule ואת שרשרת s.katz. כדאי לוודא מול ה-ground truth. כפילויות וסימון #144 כ-suspicious עשויים להוריד, אבל 0 נראה קשה.
  - **TI 100%** על 2 שורות מתוך 5 (שלוש מסומנות "not yet measured"), ו-**T2 100%** עם Backup null ו-Timeline null. ה-rubricPct מחושב רק על מה שנמדד, ולכן מנפח.
  - **T3**: עשה backup יזום ל-T2 (seq 78, 426), אבל ברובריקה שלו אין שורת Backup.

## 3 המלצות מובילות
1. **ולידציה בשרת ל-payloads של זרימת העבודה**, בתוך `apply_session_action`: לדחות escalation/bounce/disposition בלי event_id תקף מה-feed, לדחות escalation כפולה על event_id פתוח או סגור, לדחות תשובה שנייה לכרטיס, ולדחות claim על התראה שכבר claimed (או להחזיר "taken by X"). בנוסף, ב-SituationBoard ו-LeadConsole להתייחס ל-bounced ול-resolved כסגורים ב-queue וב-Oldest unacked.
2. **containment גמיש ותיק לכל אירוע**: לאפשר ל-T2 לערוך target ולבחור סוג (host isolate / account disable / session kill / block IOC), ולמנהל לאשר עם scope מתוקן. לפצל את Shared Case ל-incidents (A/B/C), כל אחד עם owner, severity ו-status משלו, ולהציג owner וגיל לכל שורה בתור של ה-Situation Board.
3. **תיקוני רובריקה**: Help-desk לפי נכונות וחלק יחסי מהכרטיסים ולא לפי ספירה. SITREP לפי תוכן (ארבעת השדות, קהל, מספרים) ולא רק כמות. Load balancing עם סף משך (למשל עומס ≥60 שניות), מדידת זמן תגובה ודילוג על חלונות pause. תגמול לדחייה מנומקת של נכס שגוי. קנס T1 על disposition בלי פתיחת הלוג. rubricPct שמציג כמה שורות נמדדו בפועל. ובתוכן: לתקן computer_name של 4720/4728 ל-DC, את file.path ‏d.rosen, את "copied" מול blocked ב-DLP, ולגבות את ה-twist בלוג אמיתי.
