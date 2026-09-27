# ti — Threat Intelligence Analyst — חוות דעת

## ציונים (1–5): ריאליזם מקצועי | חוויית משתמש | יציבות/תקינות | שיתוף פעולה | הוגנות הניקוד
**3 | 2 | 4 | 4 | 1**

- **ריאליזם 3**: שרשראות ה-TTP טובות ומשכנעות (דרייב-ביי בסגנון SocGholish, BEC עם כלל העברה, יצירת חשבון דלת-אחורית וצירופו ל-DA). ה-IOCs בפורמט נכון: SHA256 באורך 64 hex, טווחי IP אמיתיים (185.220.101.0/24 = Tor, 84.17.46.0/24 = CDN77/DataCamp), User-Agent של azcopy/10.24.0. מנגד יש סתירות פנימיות חוזרות (DMARC, LogonId, hostname, שעות), ושדות "רמז" מומצאים שמסגירים את התשובה.
- **חוויית משתמש 2**: קונסולת ה-TI עיוורת. היא לא מקבלת feed, אסקלציות או IOCs. מאגר המודיעין קבוע בקוד ולא קשור לתרחיש, וכרטיס ה-Team intel לא מציג את ה-IOC ואת הרלוונטיות שה-TI שולח.
- **יציבות 4**: לא נתקלתי בקריסה או ב-stack trace. כל 7 הפרסומים שלי נקלטו. פעולות בזמן pause נדחו כמצופה. יש באגים בשרת ובאימות שעליהם אפשר לקרוא בהמשך.
- **שיתוף פעולה 4**: המודיעין השפיע בפועל. T3 קיבל את אזהרת ה-Tor (#393), T2 ביסס בקשת בידוד על #436/#437, ו-t1a שינה disposition אחרי הניתוח של #144. כל זה קרה בצ'אט. ערוץ ה-intel הרשמי כמעט לא נקרא.
- **הוגנות 1**: מתוך 5 תאי ה-rubric, 3 הם TODO. שני הנותרים בודקים רק אם שדה אינו ריק. קיבלתי 100%, אבל אותו ציון היה מתקבל גם על פרסום ה-decoy ‏8.8.8.8.

## מה עשיתי במשמרת (ציר זמן קצר: seq + פעולה + למה)
| seq | פעולה | למה |
|---|---|---|
| 5 | `ready ti` | אחרי קריאת TIConsole/TeamIntel/SharedCase/page/computeReport |
| 26 | intel #1: אשכול BEC (T1566→T1078→T1114.003), IOCs: ‏45.142.212.100, ‏mailout-nexacorp.com, כתובת ה-gmail וכתובת ה-proton | #8 ו-#13 מצביעים על אותו מסע BEC. תחזית: בקשת שינוי פרטי בנק מבפנים |
| 29 | message | הסבר שה-DKIM/SPF של הדומיין המתחזה לא אמורים לייצר יישור (alignment) ל-nexacorp.com. ‏185.220.101.45 הוא Tor, לכן לא לחסום אותו כתשתית של התוקף |
| 45 | message: pivot | #35 כשל OTP מ-84.17.46.200 (CDN77) → לתוקף יש סיסמה אבל אין MFA. תחזית: MFA fatigue (T1621). ‏T3 אימץ את התחזית (#59) |
| 110/114 | intel #2 + התרעה: דרייב-ביי מסוג SocGholish (T1189) | #51 ו-#76. תחזית: Update.js → wscript → recon → C2 |
| 141 | message | התחזית אומתה ב-#113 (Chrome_Update_127.0.6533.js). הערה על #126: חסימת ענן לא מונעת NTLM מול AD מקומי |
| 169 | message על #144 (p.wright → DA) | חלון השינוי CHG-00712 פג, והתפקיד סותר את #18. בעקבות זה t1a שינה את ה-disposition (#188) |
| 192/200 | intel #3: הרצה אושרה (T1204.002 + T1059.007), המלצה לבודד | #166 |
| 245/248 | intel #4: ‏stage-2 ‏api-telemetry-sync.com (T1059.001/T1105) | #194 |
| 266 | **תיקון עצמי** | #240 מראה שה-stage-2 נחסם. הורדתי את "assume executed" ל-"attempted, blocked" |
| 295 | message | כרטיס ה-vishing ממופה ל-T1566.004 + T1111 ומקושר ל-story A. בקשה לבדוק את m.torres |
| 331/333 | intel #5: ‏story C (T1021.001 → T1136.002) | #291. תחזית: s.katz → DA → כניסה ראשונה. **שתיהן התממשו** (#318, #359). הצבעתי על טעות ה-LogonId |
| 364/382 | אזהרה מקצועית | שימוש חוזר ב-exit של Tor אינו ייחוס (#322/#327). ‏T3 חלק בהתחלה (#369) ואז קיבל (#393) |
| 436/437 | intel #6: המקור האמיתי הוא WS-ENG-2208 (y.dagan), לפי #410 | הצבעתי שה-hostname ‏WS-FIN-2847 שגוי, וזה מה שגרם ליעד הבידוד השגוי |
| 458 | message | השערת התכנסות A↔C דרך 10.10.20.61, ברמת ביטחון MEDIUM עד אימות DHCP |
| 510/513 | intel #7: הערכת סוף-משמרת | שרשרת ATT&CK מאוחדת, block list מלא, סדרי עדיפויות להעברת משמרת. דיווח שאין טלמטריה ל-twist (#335) |
| 531, 578 | message | #514 (T1530, ליד לא מקושר). הבחנה בין a.jones ל-r.williams לפי tunnel-IP ו-hostname. ‏T2 אימץ (#597) |
| (pause) | `intel.published` + `note.added` | נדחו: `action_not_allowed ... in status paused`. זו התנהגות תקינה |

## מה עבד טוב
- **שרשרת B ‏(SocGholish) מצוינת מקצועית**: ‏referer מאתר חדשות לגיטימי → ‏`/loader/update-check.js` → ‏`Chrome_Update_127.0.6533.js`, גרסת Chrome אמיתית, ‏PAN ‏`subtype=file` עם sha256 → ‏MDE FileCreated → ‏explorer→wscript → ‏powershell IEX → חסימה של ‏newly-registered-domain. המיפוי ל-T1189, ל-T1204.002 ול-T1059.001 נכון. חסימת ה-stage-2 היא טוויסט מקצועי מצוין: היא בודקת אם האנליסט מעדכן את ההערכה שלו (אני תיקנתי ב-#266, ‏T3 ב-#262).
- **4732 ב-#339 נאמן למקור**: ‏`MemberName="-"`, ‏`TargetDomainName=Builtin`, ‏`S-1-5-32-544`. גם 4624 type 10 ב-#263 ‏(`User32 `, svchost, ‏subject `S-1-5-18`) ו-‏UAC ‏`%%2080 %%2082 %%2084` ב-4720 נאמנים.
- **#410 ‏(Sentinel) הוא לוג מודיעיני אמיתי**. הוא נותן את ה-pivot הקריטי: מכשיר מוקצה מול מכשיר מקור. ה-TI יכול להפוך אותו להחלטת בידוד.
- **הבחנה עדינה ב-VPN**: ל-a.jones ‏(#432) ול-r.williams ‏(#312) יש אותו ‎/24 ואותו gateway. מה שמבדיל ביניהם הוא tunnel IP מחוץ ל-pool ו-hostname של desktop. זה מלמד לא להסתמך רק על geo.
- המודיעין השפיע על החלטות אמיתיות: #188, ‏#393, ‏#405 (בקשת בידוד של WS-ENG-2208 שציטטה את TI), ‏#597.

## תקלות / שגיאות מערכת (כל אחת: חומרה, שחזור מדויק, פלט שקיבלת)
1. **גבוהה: השרת מקבל `escalation.requested` עם payload ריק.** ‏#146 ‏(t1b) נקלט כ-`{}`, בלי event_id, ‏summary או iocs. ב-Shared Case הוא מוצג כ-"escalation" ריק (SharedCase.tsx:121). ‏T2 נאלץ לעשות לו bounce ‏(#165). ‏t1b אישר שהשרת קיבל אותו (#174).
2. **בינונית: `disposition.set` בלי `event_id` נקלט** (#25 ‏`{"verdict":"benign"}`). בנוסף, כרטיס help-desk נענה פעמיים ‏(#299 ואחר כך t1b, לפי #326).
3. **גבוהה (UX ותוכן במשולב): יעד הבלימה (containment target) מתמלא אוטומטית מה-hostname של כרטיס ה-T1 ואי אפשר לערוך אותו.** בגלל שלוגי story C נושאים ‏`hostname=WS-FIN-2847` (תחנת j.chen), ‏T2 ביקש בלימה על נכס שגוי ‏(#378), וה-Manager נאלץ לדחות בלימה נכונה במהותה ‏(#409). ‏T2 תיעד את זה ב-#399.
4. **נמוכה: שעון המשמרת ב-`status` ממשיך לרוץ בזמן pause וקופץ אחורה ב-resume.** ‏10m24s ‏(paused) → ‏10m7s אחרי resume. ‏26m25s ‏(paused/coverage) → ‏25m44s. ייתכן שזה בחישוב של ה-harness ולא בשרת.
5. **מידע: coverage auto-pause נכנס לפעולה רק כ-140 שניות אחרי שה-T2 נעלם** (seen=141s, ‏#551). ‏auto-resume הגיע כ-56 שניות אחרי שה-T2 חזר (#553 → ‏#554).
6. **בינונית: ל-inject ה-twist ‏(#335, "a host… beaconing to a NEW C2 domain") אין אף שורת טלמטריה ב-feed.** סרקתי את כל 103 השורות, וגם T3 סרק ‏(#505). ובכל זאת בדוח הוא מסומן `handled:true`, כי כל `escalation.requested` שמגיע אחריו נספר כטיפול (computeReport.ts:437).
7. **נמוכה: גם ל-false-lead (Marketing SaaS) אין שורת firewall בפיד.** אין מה לבדוק ואין פעולה שמאפשרת לדחות אותו, והוא תמיד `handled:false`.

## שגיאות מקצועיות בתוכן (לוג/שדה/ורדיקט/MITRE/תרחיש — עם feed id וציטוט השדה)
1. **`ee76d3093e336` ‏(#8), ‏DMARC בלתי אפשרי:** ‏`dkim=pass header.d=mailout-nexacorp.com; spf=pass smtp.mailfrom=mailout-nexacorp.com; dmarc=pass ... header.from=nexacorp.com`. ‏mailout-nexacorp.com אינו תת-דומיין של nexacorp.com, ולכן אין alignment ו-DMARC אמור להיות `fail`. בנוסף, ‏`received_0` מתוארך ל-"Mon, 15 Jun 2026" בזמן שה-ts הוא 2026-01-01. ה-MITRE ‏T1566 כללי מדי: ‏BEC בלי קישור וקובץ מתאים יותר ל-T1566 ‏(+T1534/T1598).
2. **`ef3f29b239296` ‏(#291) ו-`efef2ac740d53` ‏(#318), ‏LogonId בין מכונות:** ‏4720/4728 נרשמים עם `winlog.computer_name: WS-FIN-2847` ו-`SubjectLogonId: 0xB17C440`, שהוא ה-LogonId של סשן ה-RDP ב-WS-ENG-2093 ‏(#263). ‏LogonId הוא מזהה מקומי למכונה. בנוסף, 4720/4728 של חשבון דומיין נרשמים ב-DC ולא בתחנת עבודה. התרחיש מלמד pivot שגוי ("same LogonId"), וגם t1b ו-T3 בנו עליו.
3. **hostname שגוי ב-story C:** ‏`hostname: WS-FIN-2847` ב-#291, ב-#318 וב-#410, בזמן שה-ExtendedProperties של #410 עצמו מראים ש-WS-FIN-2847 לא מעורב (‏`Source Host Observed: WS-ENG-2208`, ‏`Actor Assigned Device: WS-ITS-1140`). זה גורם לבלימה על הנכס הלא נכון (תקלה 3).
4. **`ef8e5d70f7696` ‏(#144):** ‏`SubjectLogonId: 0x3e7` (סשן SYSTEM) יחד עם `SubjectUserSid ...-500` / ‏`it.admin` זה צירוף לא עקבי. ה-`it_verify_message` מתאר את p.wright כ-"CTO", אבל ב-#18 ‏`user_title: Legal Counsel`. חלון השינוי "05/10–05/11" פג ביחס לתאריכי המייל (יוני). לא ברור אם זה מכוון, ואם כן, זה לא מסומן כמכוון.
5. **`efae5da358c0c` ‏(#131):** ‏`raw.file.path: C:\Users\d.morgan\...` מול `file.path: C:\Users\d.rosen\...` באותו לוג.
6. **`ef4f29cb6658b` ‏(#305) ‏DLP:** התיאור אומר "d.brown **copied** 3,200 ... to personal USB", וה-raw אומר ‏`purview.action: block`, ‏`action_result: blocked`. ‏3,200 רשומות בקובץ CSV יחיד של 7.3GB הן כ-2.3MB לרשומה, וזה לא סביר. ‏`dlp.file_count: 3200` סותר את נתיב הקובץ היחיד.
7. **`e71ef8fe6f052` ‏(#322):** ‏SMB brute-force (127 ניסיונות) ממופה ל-**T1110.003 Password Spraying**. ‏brute-force על חשבון אחד הוא T1110.001. בנוסף, SMB של DC ‏(10.10.1.2:445) חשוף לאינטרנט, וזה לא ריאלי. כתובת ה-DC01 לא עקבית: ‏10.10.1.2 כאן לעומת 10.10.1.5 ב-#60.
8. **`e72ef9179794e` ‏(#327):** ‏Tor → ‏`destination.ip: 10.10.20.14` (RFC1918) בלי NAT. זו גם בדיוק כתובת ה-`gp.tunnel_ip` של r.williams ב-#312, שבעצמה מחוץ ל-pool ‏10.100.x (#18, ‏#432). נראה כמו התנגשות של הגנרטור.
9. **`e1fa55d52f1b5` ‏(#514):** ‏`vendor: Azure Activity Log` + ‏`event_category: DataPlane` + ‏`BLOBS/READ`. ה-Activity Log לא רושם קריאות data-plane, והן נמצאות ב-StorageBlobLogs.
10. **`ef1e14edce4c4` ‏(#60):** התיאור אומר "added ... as a guest user" ‏(event_type=account_create), וה-Operation הוא `Add member to group`. ‏`hostname: SRV-NXC-DC01` לאירוע Entra בענן. ‏`ConditionalAccessStatus` הוא שדה של sign-in ולא של audit.
11. **שדות "רמז" מומצאים שמסגירים את הוורדיקט:** ‏`forward.tor_exit` ‏(#13), ‏`gp.pre_auth_travel` ‏(#18), ‏`forward.hr_approved` ‏(#397), ‏`azure.normal_work_hours` ‏(#514). ‏`it_verify_message` ב-#13 אומר אפילו "almost certainly a BEC... escalate immediately". כל אלה לא קיימים אצל הספקים.
12. **שעות בתיאור סותרות את ה-ts:** "at 13:42" ‏(#51), "Seventy-two seconds" (בפועל ‏78s), "Three seconds later" ‏(#194, בפועל ‏80s עד היוצא ו-107s עד החסימה ב-#240), "22:47"/"23:02" ב-story C, וכל ה-ts הם 08:xx.
13. **`ee96d33b90e70` ‏(#13):** ‏185.220.101.45 מסומן `source.geo.country: NL`. בפועל הטווח הזה מגואלק (geolocated) ברובו ל-DE. זו טעות קלה.
14. **MITRE מוכלל:** ב-#263 ‏RDP פנימי ממופה ל-`Initial Access / T1078`. נכון יותר T1021.001 ‏(Lateral Movement) + T1078.002. ב-#339 ‏T1098 מוכלל, ונכון יותר T1098.007. ב-#166 חסר T1059.007.
15. **קוהרנטיות (לא ודאי):** ‏#424, שורת informational בלי תג, משתמשת ב-10.10.20.61, כתובת המקור של story C. אם זה מקרי, זה יוצר קורלציה שקרית (T3 בנה עליה "convergence A+C"). אם זה מכוון, חסר לו severity או תג.

## חיכוך בחוויית המשתמש (עם file:line מהקומפוננטה)
- **TIConsole.tsx:16**: הקומפוננטה מקבלת רק `act`. ל-TI אין תור, אין רשימת אסקלציות ואין IOCs מה-T1. כדי לראות את ה-IOCs שה-T1 בחרו צריך להיות T2 (T2Console.tsx:104-126). ב-Shared Case מוצג רק `what` בלי IOCs (SharedCase.tsx:119-125).
- **TIConsole.tsx:11-15**: ‏`INTEL_REPO` קבוע בקוד (PuTTY/Cobalt Strike, ‏mega.nz, ‏decoy ‏8.8.8.8) ולא קשור לתרחיש. אף אחד מהשלושה לא הופיע בפיד (0 התאמות ל-putty/mega מתוך 103 שורות). מנגנון ה-decoy לא מלמד כלום אם ה-advisory לא רלוונטי.
- **TIConsole.tsx:17,32**: ‏`ioc` הוא מחרוזת חופשית אחת, בלי סוג, בלי מערך ובלי אימות פורמט. ה-T1 שולחים `iocs:[{type,value}]` מובנה.
- **TIConsole.tsx:20,41**: אפשר לפרסם עם `actor` בלבד. אין דרישה ל-IOC, להמלצה או לקישור ל-event_id או לאסקלציה.
- **TeamIntel.tsx:15-21**: הכרטיס לא מציג `ioc` ולא `relevance`, כלומר הצוות לא רואה את האינדיקטורים שה-TI פרסם. גם ActivityLog.tsx:29 מציג רק את `actor`.
- **SecondaryPanels.tsx:13-14,33**: ה-Team intel מוסתר בתוך "Team context", שמקופל כברירת מחדל, בטאב השלישי. אין badge ואין התראה על intel חדש. לכן כל ההשפעה שלי עברה דרך הצ'אט.
- **page.tsx:926-931**: ההערה מגדירה את ‏`'ti'` כענף "backward-compatibility with older sessions". לפי הקוד התפקיד legacy, אבל הוא עדיין מוקצה בסשן v2.
- **ActivityLog.tsx:32 מול T2Console.tsx:186**: ה-ActivityLog קורא `p.summary`, וה-T2 שולח `label`. לכן תווית ה-pin לא מוצגת.
- אין פעולת "correct/retract intel". את התיקון ב-#266 יכולתי לעשות רק בצ'אט, ו-intel #4 נשאר בכרטיס עם "assume executed".

## הדוח שלי (Shift review) — האם הוגן? מה חסר/שגוי?
הכרטיס: ‏`rubricPct: 100`, ‏`Attribution accuracy: 12`, ‏`Next-step prediction: 12`. שלושה תאים `not yet measured`: ‏Actionable-rate, ‏Time-to-action, ‏IOC precision. ‏`roleActions: 7`, ‏`opened: 18`.

**לא הוגן, וזה לא rubric הוגן ל-TI:**
- ה-"Attribution accuracy" ‏(computeReport.ts:336) בודק רק ש-`actor` ו-`technique` לא ריקים. זה לא בודק דיוק. פרסום "APT29 · T1000" היה מקבל אותו ציון.
- ה-"Next-step prediction" ‏(computeReport.ts:337) בודק רק ש-`next_expected` לא ריק. אין השוואה לאירועים שהגיעו אחר כך. שתי תחזיות שלי התממשו במלואן (s.katz→DA ו-RDP ‏#318/#359, קובץ ה-JS ‏#113, ‏MFA/vishing ‏#273), ולא קיבלתי על זה שום קרדיט נוסף.
- "IOC precision" הוא TODO. לכן פרסום ה-decoy ‏8.8.8.8, שהוא כל הרעיון הפדגוגי של G-17 (TIConsole.tsx:8-10), לא נענש.
- 18 הודעות ה-briefing, התיקון העצמי והאזהרה על Tor, שהם עיקר הערך של TI במשמרת, לא נמדדים. ‏`message.sent` לא נמצא ב-ROLE_ACTION_TYPES.
- RoleGuideModal.tsx:27 מבטיח "Attribution accuracy, Predicting the next step", אבל בפועל זו מדידת נוכחות שדות.
- בשורה התחתונה: ה-100% שלי נכון במקרה. מי שהיה מפרסם intel ריק-מתוכן אחד היה מקבל אותו ציון.

## 3 המלצות מובילות
1. **לחבר את ה-TI לזרימה.** להעביר ל-TIConsole את `escalations`/`feed`, ולהציג תור "IOCs שחולצו", כלומר ה-`iocs[]` מכל אסקלציה ו-evidence.pinned. לאפשר intel מקושר ל-`event_id` עם `iocs:[{type,value}]` מובנה ופעולת "correct/retract". להציג `ioc`+`relevance` ב-TeamIntel, ולהציף intel חדש (badge או toast, לא טאב מקופל).
2. **rubric אמיתי ל-TI.** ‏IOC precision: חיתוך ה-IOCs שפורסמו מול IOCs שמופיעים ב-raw של אירועי תקיפה (ground truth), עם קנס על decoy/Tor/‏8.8.8.8. ‏Next-step: התאמה של טכניקות ב-`next_expected` מול `mitre_technique` של אירועי תקיפה שהגיעו אחרי הפרסום. ‏Actionable-rate: אחוז ה-intel שהמלצתו מוזכרת ב-containment או ב-report שבא אחריו. ‏Time-to-action: הזמן מאירוע התקיפה הראשון בסיפור ועד ה-intel הראשון.
3. **ניקוי תוכן ואימות בשרת.** לתקן DMARC ‏(#8), ‏hostname ו-LogonId ב-story C (שורש בעיית הבלימה על WS-FIN-2847), ‏DLP ‏copied/blocked, ‏T1110.003→.001, שעות בתיאור שסותרות את ה-ts, ולהסיר שדות רמז מומצאים (`forward.tor_exit`, ‏`gp.pre_auth_travel`, ‏`forward.hr_approved`). לגבות כל twist ו-false-lead בשורות טלמטריה. בשרת: לדחות `escalation.requested` ו-`disposition.set` בלי `event_id`, לדחות מענה כפול לכרטיס, ולאפשר עריכה של יעד הבלימה.
