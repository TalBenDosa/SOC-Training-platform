# t1b — Tier-1 (אנליסט B, מיקוד בחלוקת עבודה ותפוקה) — חוות דעת

## ציונים (1–5): ריאליזם מקצועי | חוויית משתמש | יציבות/תקינות | שיתוף פעולה | הוגנות הניקוד
**3 | 3 | 2 | 4 | 2**

- ריאליזם 3: שלושת הסיפורים (BEC/זהות, דרייב-באי SocGholish, חשבון Domain-Admin זדוני) קוהרנטיים, וה-LogonId/PID/SID מתחברים בין לוגים (למשל wscript pid 9312 עובר מ-#166 ל-#194, ו-0xB17C440 מופיע ב-#263, #275, #291 ו-#318). מנגד יש הרבה שדות מומצאים, סתירות סכמה, רמזים שמוטמעים בתוך הלוג וזמנים סיפוריים שסותרים את שעון המשמרת.
- יציבות 2: לא הייתה קריסה, וה-pause הידני, ה-coverage-pause וה-auto-resume עבדו בצורה חלקה. אבל השרת מקבל escalation ריק, ורדיקט לא חוקי, event_id שלא קיים ותשובה כפולה לטיקט. אין שום אימות סמנטי בשרת.
- הוגנות 2: התא "Backup & load-balancing" נתן לי קרדיט על **התנגשות claim**, לא על גיבוי (פירוט בהמשך).

## מה עשיתי במשמרת (ציר זמן קצר: seq + פעולה + למה)
- **#6** ready. **#16**: הסכמתי לחלוקה ש-t1a הציע (אני לוקח endpoint/network/AD/Linux, t1a לוקח email/identity/cloud).
- **#21, #23, #24, #25 (probes)**: claim על id שלא קיים, ורדיקט `probably_fine`, disposition על id שלא קיים, disposition בלי event_id. **כל הארבעה חזרו OK** (פירוט בתקלות). אחר כך שחררתי (#30) ותיקנתי ל-benign (#32/#33, double-click מכוון: נכתבו שתי שורות זהות).
- **#48–#58**: benign מהיר על VPN (#18), docker (#27) ו-RDP פנימי (#31).
- **#61 → #66 → #68**: claim, TP ו-escalation מלא על #35 (כשל OTP ב-VPN של r.williams מ-84.17.46.200 = טווח של VPN מסחרי, מקושר ל-inbox rule ב-#13).
- **#93–#118**: benign על 7 לוגי רעש. טעות מקצועית שלי: סימנתי גם את #51 (כתבת logisticsweekly) כ-benign. תיקנתי ל-suspicious ב-#151 אחרי ש-T2/T3 זיהו watering-hole.
- **#122/#123 → #146**: שלחתי בטעות **escalation עם payload ריק `{}`** (בגלל כשל בסקריפט שלי). השרת קיבל אותו, ו-T2 החזיר אותו ב-bounce ב-#164 עם `event_id:"undefined"`.
- **#173**: escalation אמיתי על #113 (הורדת Chrome_Update_127.0.6533.js, עם השרשרת #51 → #76 → #113 וכל ה-IOC-ים).
- **#180 → #196 → (REJECTED בזמן pause) → #217**: escalation קריטי על #166 (wscript מריץ את ה-JS). הפעולה נדחתה באמצע הרצף בגלל pause ידני (ה-disposition עבר וה-escalation לא), ושלחתי שוב אחרי ה-resume.
- **#230 → #239**: escalation קריטי על #194 (powershell IEX ל-api-telemetry-sync.com). **התנגשות**: t1a עשה claim על אותו אירוע 10 שניות אחריי (#234) ושלח escalation כפול (#261).
- **#251–#257**: עשיתי batch-claim על 5 לוגים (בדיקת עומס מכוונת). **#268: ה-Manager שלח לי `coordination.nudge` (load=5) אחרי כ-55 שניות**, ואחריו הודעה עם הנחיה ברורה. שחררתי את כולם אחרי disposition (#294–#310).
- **#319**: ענה לטיקט ה-vishing (refuse & escalate). **כפילות**: t1a ענה 40 שניות קודם (#299) והשרת קיבל גם את שלי.
- **#344 → #351**: escalation קריטי על #318 (s.katz נוסף ל-Domain Admins), כולל #291, #263 ו-#275. **התנגשות נוספת**: t1a עשה claim 5 שניות לפניי (#341), ה-claim שלי דרס אותו בשקט, ו-t1a שלח escalation מקביל (#357).
- **#379**: escalation קריטי על #312 (VPN של r.williams **הצליח** מלונדון עם MFA, 10 דקות אחרי ה-containment).
- **#422**: escalation קריטי על #359 (s.katz ב-RDP ל-WS-ENG-2093 עם SeDebug/SeBackup), כולל #339 ו-#386. TP בלי escalation על #322 ו-#327 (חסימות, IP של Tor מאותו טווח כמו סיפור A).
- **#453–#502**: עשיתי disposition לכ-25 לוגי רעש שהצטברו.
- **(coverage pause #551 עד auto-resume #554)**, ואחריו **#560**: escalation עם ביטחון נמוך על #432 (VPN של a.jones מ-82.102.14.211, אותו /24 כמו ההשתלטות על r.williams).
- **#594**: claim על #518 (התקנת Nessus). המשמרת הסתיימה לפני ה-disposition, כך שה-claim נשאר פתוח.
- סיכום: 9 escalations (8 אמיתיים ואחד ריק), 86 dispositions, תשובה לטיקט אחד ו-nudge אחד שקיבלתי.

**בדיקת take-over מבוקרת לא התאפשרה באופן טבעי**: t1a אף פעם לא השאיר claim נטוש יותר מדקה-שתיים, ובזמן שבדקתי (`activeClaims`) לא היה אף claim פעיל. גם לא היה claim ישן (מעל 5 דקות) שאפשר היה לבדוק מולו. במקום זה נתקלנו פעמיים ב-take-over לא מכוון (התנגשויות), וזה ממצא חשוב יותר.

## מה עבד טוב
- **ה-nudge של ה-Manager הגיע** (seq 268, load=5, target = ה-uid שלי), כ-55 שניות אחרי שחצית את סף ה-3. ה-Manager צירף גם הודעה אנושית שהסבירה מה לשחרר. זה מנגנון עבודה אמיתי.
- **Coverage pause**: "No Tier-2 online right now", והשיחה נשארה פתוחה. auto_resume הגיע בלי התערבות. דחיית הפעולות בזמן pause עקבית והודעת השגיאה מדויקת (`action_not_allowed: … in status paused`, ובממשק היא מתורגמת ל-"The shift is paused — actions resume when it does." ב-`src/lib/team/format.ts:43-44`).
- **Bounce של T2 עבד כמו שצריך**: ה-escalation הריק שלי הוחזר עם סיבה ברורה, והסטטוס מופיע ב-My escalations (`T1Console.tsx:86-96`).
- הלוגים הטובים ביותר ברמת נאמנות: 4624 type 10 ב-#359 (LogonProcessName User32, ProcessName svchost.exe, IpPort, SIDs), 4672 עם PrivilegeList רב-שורתי, 4732 על ה-member server עצמו (#339), 4771 עם Status 0x18 (#496), ו-4625 עם SubStatus 0xC000006A (#455).
- MITRE ברוב המקרים נכון: T1189 על #76 ו-#113, T1204.002 על #166, T1059.001 על #194, T1098 על #318.

## תקלות / שגיאות מערכת (כל אחת: חומרה, שחזור מדויק, פלט שקיבלת)
1. **[גבוהה] השרת מקבל `escalation.requested` ריק.** שחזור: `act t1b escalation.requested '{}'`. פלט: `OK seq=146 escalation.requested`. התוצאה: כרטיס ריק מגיע ל-T2, נכנס ל-Evidence של ה-Shared Case כ-"escalation" (`SharedCase.tsx:120-123`), ה-bounce נרשם עם `"event_id":"undefined"`, והוא נספר ב-escCount שלי ובמכנה של Escalation precision. שער האיכות (T1-6) קיים רק בצד הלקוח (`T1Console.tsx:108-116`). צריך אימות בשרת: event_id קיים בפיד, summary, ומינימום IOC.
2. **[בינונית] ורדיקט לא חוקי מתקבל.** `act t1b disposition.set '{"event_id":"ee66d2f00202e","verdict":"probably_fine"}'` החזיר `OK seq=23`. הממשק מציג אותו ב-dropdown (`T1Console.tsx:215`) ואף כפתור לא מודגש. ב-AAR רצף "לא חוקי ואז תקין" נספר כ-**Self-correction** (`computeReport.ts:277-286`), כלומר אפשר לנפח את הציון בכוונה.
3. **[בינונית] פעולות על id שלא קיים מתקבלות.** `alert.claimed {"event_id":"e0000deadbeef"}` החזיר `OK seq=21`. `disposition.set` על אותו id החזיר `OK seq=24`, ו-`disposition.set '{"verdict":"benign"}'` בלי event_id החזיר `OK seq=25`. claim פיקטיבי נספר ב-`openLoadByUser` (`projections.ts:38-49`) ולכן יכול לייצר nudge שגוי על עומס ולהטות את ה-AAR.
4. **[בינונית] אין נעילת claim בשרת, ו-take-over שקט.** נצפה פעמיים: #230 מול #234 (הפרש 10 שניות), ו-#341 מול #344 (הפרש 5 שניות). התוצאה היא שני escalations כפולים (#239 ו-#261, #351 ו-#357). השרת מבדיל רק לפי role ו-phase (`0071…sql:139`), והממשק מבצע auto-claim כשהמודאל נפתח ורק אם הלקוח עדיין לא ראה claim (`T1Console.tsx:121-124`), כך שחלון המרוץ שווה ל-latency של ה-realtime. המחזיק הקודם לא מקבל שום הודעה שה-claim שלו נלקח.
5. **[נמוכה-בינונית] תשובה כפולה לטיקט מתקבלת.** `ticket.answered {"ticket_seq":273,…}` החזיר `OK seq=319`, אחרי ש-t1a כבר ענה ב-#299. הממשק מסתיר את הכפתורים אחרי תשובה (`InjectFeed.tsx:59`), אבל במרוץ זה קורה, והציון נותן קרדיט לשני המשיבים.
6. **[נמוכה] double-click.** שני `disposition.set` זהים שנשלחו במקביל נכתבו כשתי שורות (#32 ו-#33). בממשק יש הגנה של idempotency key לשתי שניות (`page.tsx:320-332`), כך שזה קורה רק מחוץ לממשק. אין dedupe סמנטי בשרת. זו התנהגות סבירה, אבל ה-dispCount מתנפח.
7. **[נמוכה] Pause באמצע רצף escalate.** ה-disposition עבר (#196) וה-escalation נדחה. בממשק המודאל נשאר פתוח עם הטופס (`T1Console.tsx:155` מאפס רק כש-`ok`), וזה טוב. חסר רק רמז בתוך המודאל ("the shift paused — your report is kept").
8. **[נמוכה, harness] `status` בזמן pause** המשיך לספור (10m23s) וירד ל-10m13s אחרי ה-resume, כי paused_ms מתעדכן רק בסיום ה-pause. כדאי לבדוק שהשעון בממשק לא מתנהג כך.

**איכות הודעות השגיאה**: הטקסטים שהשרת מחזיר (`action_not_allowed: disposition.set for role t1 in status ended`) מדויקים וטכניים, והממשק מתרגם אותם יפה. הבעיה היא לא בטקסט אלא ב**היעדר דחיות**: payload שגוי אף פעם לא מחזיר REJECTED.

## שגיאות מקצועיות בתוכן (לוג/שדה/ורדיקט/MITRE/תרחיש — עם feed id וציטוט השדה)
1. **#8 `ee76d3093e336`**: `email.dmarc: "pass"` מול `auth_results: dkim=pass header.d=mailout-nexacorp.com; spf=pass smtp.mailfrom=mailout-nexacorp.com; … header.from=nexacorp.com`. אין יישור דומיינים (alignment) ולכן DMARC צריך להיות **fail**. הלוג מלמד משהו שגוי (TI זיהה את זה בזמן אמת). בנוסף, `vendor: "Microsoft 365 Unified Audit Log"` לא רושם מסירת דואר נכנס (זה Message Trace או MDO EmailEvents). `file.size` משמש לגודל מייל, ותאריכי Received הם 15 ביוני לעומת ts.
2. **#11 `ee66d2f00202e`** (Sysmon 22): יש `winlog.event_data.QueryType`, שאינו שדה של Sysmon, וחסר `QueryStatus`.
3. **#38 `eee6d3b985007`**: `vendor: MySQL Enterprise Audit` אבל `log.source=mysql_slow_query_log` (מנגנון אחר). בשאילתה על `trading_positions` מופיעים `w.zone = 'A' ORDER BY w.shelf_number`, שאריות סכמה של מחסן (העתק-הדבק מחברת לוגיסטיקה).
4. **#120 `e04e8288a4ccd`**: `av.total_engines=72` על Microsoft Defender AV (זה מושג של VirusTotal), ו-`event_type: av_detection` לסריקה נקייה.
5. **#121 `ef7e814130571`**: אירוע 5145 (SMB share) מסווג `event_type: cloud_storage_access`.
6. **#131 `efae5da358c0c`**: ה-parsed `file.path: C:\Users\d.rosen\Downloads\…` סותר את ה-raw `C:\Users\d.morgan\Downloads\…`.
7. **#194 `e88ed758451ff`**: `severity: critical` אבל `is_detection: false`, בזמן ש-#166 (high) מסומן `is_detection: true`. זה לא עקבי.
8. **#237, #291, #318**: 4720 ו-4728 לחשבונות **דומיין** עם `winlog.computer_name=WS-FIN-2847.nexacorp.com`. אירועים כאלה נרשמים על DC, לא על תחנת עבודה של כספים. לעומת זאת, 4732 ב-#339 על member server נכון.
9. **#386 `e00f72cc8f8b3` ו-#237**: שדות `it_verify_result` / `it_verify_message` בתוך הלוג, למשל "*…must be escalated, not cleared.*". זה חושף את התשובה (הפרה של no-hints).
10. **תיאורים סיפוריים עם שעון פנימי**: #51 "at 13:42", #76 "Seventy-two seconds into the page view…", #113 "At 13:45:40…", #166 "At 13:47:08…", #194 "Three seconds later…", #263 "At 22:47", #359 "At 23:02". יש כאן סתירה לשעון המשמרת (08:xx), וה-description עושה את עבודת הקורלציה במקום האנליסט.
11. **VPN (GlobalProtect)**: `gp.tunnel_ip` שווה ל-IP ה-LAN של התחנה (#432 `10.100.50.23` = LT-DEV-0931 מ-#11, ו-#312 `10.10.20.14` = WS-FIN-2847). `gp.client_hostname=WS-FIN-2847` (דסקטופ on-prem) מופיע גם אצל r.williams וגם אצל m.edwards. ערימת ה-MFA לא עקבית (`Azure AD + MFA`, `LDAP+OTP`, `Duo TOTP`), ושמות ה-gateway לא עקביים (`gw-nexacorp-lon01` / `VPN-GW-LON-01` / `gp.nexacorp.com` / "NXC-VPN-GW01" בתיאור של #35). `gp.pre_auth_travel` (#18) הוא שדה מומצא.
12. **#312 `efff2ae073a78`**: `severity: informational` ל-**VPN מוצלח עם MFA** לחשבון שנפרץ והוכל. זה אולי האירוע החשוב ביותר בסיפור A, ובגלל ה-severity הוא לא נכנס לתור ה-T1 (`T1Console.tsx:39` מסנן רק high/critical). אותו דבר חל על #35 (low).
13. **#322 `e71ef8fe6f052`**: `mitre_technique: T1110.003` (Password Spraying) לחתימת "SMB-BruteForce" עם `repeatcnt=127` נגד יעד אחד. T1110.001 מתאים יותר. בנוסף, זה מרמז ש-445 של DC חשוף מהאינטרנט ולא מוסבר.
14. **#327 `e72ef9179794e`**: `protocol: "SSH"` (צריך tcp), ושדות לא-PAN (`rule.name`, `rule.action`, `session.blocked`) תחת vendor PAN-OS.
15. **#207 `e87ed73f13212`**: ב-raw של "MDE" אין אף שדה של MDE (`Classification=InformationalExpectedActivity` הוא גם רמז), ו-`parent_name: "Task Scheduler"` (במציאות svchost.exe).
16. **#149 `ef5e5d256b200`**: `source.geo.city_name=Ra'anana` על IP פרטי 10.20.30.15.
17. **Kubernetes לא עקבי**: #109 `kubernetes.audit.*` + `cloud.provider=azure`, #155 `k8s.audit.*`, #254 `cloud.provider=gcp` (אותו קלאסטר).
18. **#336 (4723) ו-#504 (4724)**: שדות מומצאים `change.type`, `target.user` במקום TargetUserName/SubjectUserName.
19. **לוגים ממוחזרים זהים בסוף המשמרת**: #521 = #327, #577 = #322, #539 = #70, ו-#524/#532 = #435 (אותו תוכן עם id חדש). הלולאה בולטת לעין ופוגעת בריאליזם.

## חיכוך בחוויית המשתמש (עם file:line מהקומפוננטה)
- **`T1Console.tsx:223` / `:270`, כפתור "Take over"**: שולח `alert.claimed` מיד, בלי אישור, בלי להציג את גיל ה-claim ("claimed 12s ago" לעומת "4m ago") ובלי הודעה למחזיק הקודם. אנליסט לא יכול להבחין בין "נטוש" ל"עובד עליו עכשיו".
- **`T1Console.tsx:121-124`, auto-claim בפתיחת המודאל**: שם אופטימי. אם ה-realtime מאחר בשנייה, שני T1 נכנסים לאותו לוג. זה קרה פעמיים ב-25 דקות. ממילא אין קשר ל-TTL של 5 דקות, כי השרת לא אוכף כלום.
- **`T1Console.tsx:39`, התור מסנן לפי severity בלבד**: אירועי story קריטיים עם severity נמוך (#35 low, #312 informational) לא נכנסים לתור לעולם. זה מכוון חלקית (שיקול דעת), אבל אין אפילו אינדיקציה של "related to escalated entity".
- **`T1Console.tsx:215`, ה-dropdown "Pick a log"** מכיל את כל הפיד (135+ פריטים) בפורמט `#seq description`, בלי סינון מקור. בחלוקה לפי lanes (שהצוות אימץ כבר בדקה הראשונה) אין פילטר "הlane שלי".
- **`T1Console.tsx:129`**: שחרור אוטומטי קורה רק ב-FP/benign. ב-TP/suspicious בלי escalation נשאר claim, אבל `projections.ts:28` ממילא מוחק claim בכל disposition, כך שהקוד וה-projection לא מסכימים על המשמעות.
- **`page.tsx:749-758`, באנר ה-nudge** זהה לכולם, כולל ה-target עצמו: "*If you're light, take the next case*". האנליסט העמוס לא מקבל הנחיה אישית ("release claims you're not working"). במקרה הזה הגיעה הנחיה כזו רק כי ה-Manager כתב אותה ידנית בצ'אט.
- **`InjectFeed.tsx:61-62`**: שתי תשובות קבועות לטיקט. אין שדה חופשי (שם המשתמש, מספר המתקשר) ואין דרך לתעד את ה-verification. "Handle — verified caller, no code shared" מנוסח באופן עמום ומטעה.
- **`SharedCase.tsx:120-123`**: escalation ריק נכנס ל-Evidence כשורה "escalation" בלי חומרה, ואין איך להסיר אותו.

## הדוח שלי (Shift review) — האם הוגן? מה חסר/שגוי?
ציון כולל: rubricPct 59. escCount 9, dispCount 86, dispAcc 89%, escQuality 89.
- **Backup & load-balancing = 8, לא הוגן (קרדיט שגוי).** ה-note אומר "took an alert off an overloaded teammate", אבל הקוד (`computeReport.ts:224-227`) סופר **כל** claim על אלרט שחבר מחזיק בתוך TTL, בלי לבדוק שהחבר עמוס ובלי לבדוק את גיל ה-claim. ה-take-over היחיד שלי הוא #344 על #318, **התנגשות** 5 שניות אחרי ה-claim הטרי של t1a, שגרמה ל-escalation כפול. בפועל המדד מתגמל "חטיפת" claims. בנוסף, עזרה אמיתית שנתתי (לקחתי את #336 ו-#447 מה-lane של t1a כשהם חיכו) לא נמדדת בכלל, כי שם לא היה claim קודם. בגלל שבדיקת take-over מבוקרת לא התרחשה, הציון הנכון לתא הזה הוא null או 0, לא 8. עבור T2/T3 (שורה 234) הקוד כן בודק "same-role peer overloaded", ורק עבור T1 חסרה הבדיקה.
- **Self-correction = 8, חשוד.** ההשערה שלי היא שזה נובע מה-probe `probably_fine` שהוחלף ב-benign (רצף "לא נכון ואז נכון"), או מ-#51 (benign ואז suspicious), שהוא תיקון אמיתי. לא ניתן להבחין ביניהם, ואפשר לנפח את התא בכוונה עם ורדיקטים לא חוקיים.
- **Help-desk tickets = 4, לא הוגן בשני הכיוונים.** קיבלתי קרדיט על תשובה **כפולה** אחרי t1a. ומנגד, עם טיקט אחד במשמרת והפסים (3, 2, 1), התקרה היא 4/12 לכל שחקן.
- **Escalation precision = 4 (40–59%).** ה-escalation הריק נספר במכנה. זו הוגנות חלקית: אני שלחתי אותו, אבל השרת היה צריך לדחות אותו. ה-lead בביטחון נמוך (a.jones) כנראה נספר נגדי, וזה לגיטימי, אבל זה מעניש שליחה של "suspicious, investigate", שהממשק עצמו מעודד (`T1Console.tsx:42`, `:149`).
- **Time-to-triage 12, Handoff 8, Card completeness 8**: סבירים. dispCount 86 כולל כפילויות ו-probes (ורדיקט לא חוקי, id פיקטיבי, id undefined).
- **חסר בדוח**: אין מדד לחלוקת lanes או לכיסוי (כמה מה-lane שלי עשיתי לו disposition), אין מדד ל-"responded to nudge" (שחררתי 5 claims אחרי ה-nudge, וזה לא מופיע), ואין עונש על ה-claim שנשאר פתוח בסוף (#518).

## 3 המלצות מובילות
1. **אימות סמנטי בשרת ב-`apply_session_action`**: event_id חייב להתאים ל-feed.event בסשן. verdict חייב להיות אחד מ-true_positive/false_positive/benign/suspicious. `escalation.requested` חייב summary, observations (לפחות 12 מילים) ולפחות IOC אחד. `ticket.answered` מותר רק פעם אחת לכל ticket_seq. כל אחד מאלה צריך להחזיר REJECTED ידידותי (למשל `unknown_event`, `invalid_verdict`, `already_answered`). זה סוגר את תקלות 1, 2, 3 ו-5 ואת ניפוח הציון.
2. **לחזק את ה-claim**: לדחות בשרת `alert.claimed` על claim של מישהו אחר שגילו פחות מ-TTL, אלא אם נשלח `takeover:true` מפורש. להציג בממשק "claimed by X · 12s ago" עם אישור, ולשלוח למחזיק הקודם הודעה על ה-take-over. בנוסף, לתקן את `computeReport.ts:226` כך שייספר take-over רק אם המחזיק היה עמוס (≥ OVERLOAD_CASES) **או** ה-claim היה ישן (למשל מעל 2 דקות), ולא כולל התנגשויות של שניות.
3. **ניקוי תוכן**: להסיר את `it_verify_*` ואת ה-descriptions הסיפוריים עם שעון פנימי מהלוגים. לתקן את DMARC ב-#8, את 4720/4728 ל-DC, את gp.tunnel_ip (מאגר VPN נפרד), ואת ה-severity של #312 (high). לאחד סכמות (k8s, VPN, MDE raw), ולהוסיף וריאציה לרעש הממוחזר כדי שלוגים לא יחזרו זהים.
