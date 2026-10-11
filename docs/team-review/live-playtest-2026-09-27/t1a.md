# t1a — Tier-1 (t1) — חוות דעת

## ציונים (1–5): ריאליזם מקצועי | חוויית משתמש | יציבות/תקינות | שיתוף פעולה | הוגנות הניקוד
**3 | 3 | 4 | 3 | 2**

- ריאליזם 3: שדות ה-raw עשירים, ויש קורלציות מצוינות בין לוגים (אותו TargetLogonId/record_id בין 4624 ל-4672, guest vendor שחוזר ב-#60 וב-#489). מנגד יש הרבה שגיאות: שדות שמסגירים את התשובה, שעוני תיאור שלא תואמים את ה-ts, אירועי דומיין שנרשמים על תחנת עבודה, ולוגים ממוחזרים זהים (פירוט בהמשך).
- חוויית משתמש 3: התור, ה-SLA ושער האיכות של ההסלמה טובים. ה-claim הוא נעילה רכה בלבד בלי אכיפה בשרת, תשובה לכרטיס היא טקסט קבוע, ובקשת "help desk" מסוג update אי אפשר לענות עליה בכלל.
- יציבות 4: לא הייתה אף קריסה. השהיית coverage והחידוש האוטומטי עבדו, ופעולות נדחו כמו שצריך בזמן pause/ended. הבעיה: השרת מקבל payloads לא תקינים.
- שיתוף פעולה 3: חלוקת עבודה לפי מקורות סוכמה בתוך דקה. עם זאת היו 3 התנגשויות claim (#194, #318, #312) ושתיים מהן הניבו הסלמות כפולות.
- הוגנות 2: ה-rubric סופר כמויות ולא בודק נכונות בכרטיס help-desk, וסיווג "suspicious" נספר תמיד כשגוי (פירוט בסעיף הדוח).

## מה עשיתי במשמרת (ציר זמן קצר: seq + פעולה + למה)
- #12: הצעתי ל-t1b חלוקה: אני על email/identity/cloud והוא על endpoint/network. הוא אישר ב-#16 והמנהל אישר ב-#22.
- #14→#36: claim ל-#8 (פישינג "Direct Deposit" ל-j.chen), סיווג TP והסלמה (high, contain). IOCs: `45.142.212.100`, `mailout-nexacorp.com`, `hr.nexacorp.helpdesk@gmail.com`, `bounce-hr@mailout-nexacorp.com`. T2 אישר קבלה ב-#44.
- #20→#43: claim ל-#13 (New-InboxRule "SyncBackup" → `rwilliams.backup@proton.me` מ-Tor `185.220.101.45`), סיווג TP והסלמה critical. T2 אישר קבלה, הגיש דוח והפעיל containment.
- #71/#75/#83: סיווג benign ל-#60 (guest vendor), #19 (Teams) ו-#47 (שכר פנימי).
- #103+#105: #87 (k.taylor, ErrorNumber 53003 BlockedByConditionalAccess, AppId של Azure CLI) סווג suspicious עם case note. הסיבה: חסימת CA מוערכת רק אחרי הצלחת הגורם הראשון, כך שייתכן שהסיסמה תקפה.
- #135/#140: סיווג benign ל-k8s #109 ו-#124.
- #154→#167: לקחתי את #144 (4728: p.wright ל-Domain Admins) מהנתיב של t1b כי הוא היה עמוס. סגרתי benign על בסיס CHG-00712 המאושר.
- #185/#186: תיקון עצמי. TI הצביע שחלון ה-CHG (05/10–05/11) כבר עבר ושהתפקיד בספרייה סותר (Legal Counsel מול CTO). שיניתי ל-suspicious והסלמתי low-confidence (medium, investigate). T3 אישר קבלה ב-#212.
- #234→#261: #194 (wscript→powershell IEX, critical) נראה לא מתופס אחרי חריגת SLA, אז תפסתי אותו. בפועל t1b תפס אותו ב-#230, 4 שניות לפניי. **נוצרה הסלמה כפולה** (#239 של t1b ו-#261 שלי). לא שמתי את ה-hash של powershell.exe כ-IOC כי זו הבינארית החתומה של Microsoft.
- #297/#299: תיאמתי עם t1b וענית ראשון על הכרטיס #273 (vishing לקוד MFA) עם "Refuse & escalate". ב-#308 הוספתי note עם הפרטים שכפתור הכרטיס לא מאפשר לתעד.
- #314–#332: סיווג TP ל-#265 (MDE critical) ול-#240 (PAN block-url ל-`api-telemetry-sync.com`). הצמדתי אותם כ-evidence במקום לפתוח הסלמה כפולה, לפי הנחיית T2.
- #341→#357: story C. סיווג TP ל-#263/#275/#291 והסלמה critical אחת על #318 (s.katz ל-Domain Admins) עם כל השרשרת. **התנגשות שנייה**: t1b תפס את #318 ב-#344, חמש שניות אחרי ה-claim שלי ב-#341, ודרס אותו בשקט. גם הוא הסלים (#351).
- #381→#387: תפסתי את #312 אחרי ש-t1b כבר הסלים אותו. זו טעות שלי, ושחררתי מיד.
- #402/#406: #305 (Purview DLP, d.brown, 3,200 רשומות PII ל-USB, **blocked**) סווג TP והוסלם medium כ-insider risk.
- #414/#416: #322 (PAN IPS, SMB brute force מ-Tor אל DC01:445, blocked) סווג TP והוסלם medium. ציינתי שחשיפת 445 של DC לאינטרנט היא הבעיה המהותית, ושאין כאן ייחוס (attribution) ל-story A.
- #438/#441: #397 (inbox rule של s.patel ל-outlook.com האישי מ-IP פנימי, "leave") סווג benign עם הערת מדיניות.
- #452/#457/#460: #410 (Sentinel) סווג TP, והעברתי לצוות עובדות scoping: המכשיר של m.torres הוא WS-ITS-1140, ומקור ה-RDP WS-ENG-2208 שייך ל-y.dagan. הצעתי ש-WS-ENG-2208 יהיה יעד הבידוד, לא WS-FIN-2847.
- #511/#515: #447 (UEBA l.harris 02:15) סווג suspicious ולא הוסלם, כי אין IP, מכשיר או sign-in לבצע pivot עליהם.
- #526–#544: סיווג benign ל-#270, #489, #400 ו-#90.
- #562–#569: #514 (azcopy, 14.2GB מ-contracts, t.harris, אחרי שעות העבודה) סווג suspicious והוסלם low-confidence.
- #577 (רפליקה של #322): הפעולות נדחו כי ה-session כבר הסתיים.
- **החמצה שלי**: המנהל ביקש ממני (#236) לאמת את ה-false lead של Marketing SaaS. לא מצאתי בפיד שום לוג העברה גדולה, ולא חזרתי עם תשובה בצ'אט. בדוח זה מופיע כ-`handled:false`.

## מה עבד טוב
- **תור ה-T1** (`T1Console.tsx:37-41`): מיון לפי חומרה×גיל ותג SLA על שעון השרת. תג "⚠ unclaimed" ל-orphan (`:64`) הוא בדיוק מה שהיה חסר לי ב-#194.
- **שער האיכות להסלמה** (`:108-116`): חובה disposition של TP או suspicious, סיכום, לפחות 12 מילים של observations ולפחות IOC אחד. ה-snapshot המלא של הלוג נשלח עם ההסלמה (`:136-143`). זה מחייב כתיבה מקצועית, ו-T2 עבד ישירות מה-raw.
- **story B** (#51→#76→#113→#131→#166→#194→#240→#265) בנוי מצוין. אפשר לגלות אותו רק מהראיות: referer, קובץ .js, wscript, PowerShell cradle, חסימת newly-registered-domain. בנוסף MDE הרג את התהליך. ה-PID-ים וה-hash-ים עקביים בין PAN ל-MDE.
- **story C**: קורלציה ברמת מקצוען. TargetLogonId `0xB17C440` זהה בין #263 ל-#275, record_id רציף (2214905/2214906), ויש ניגוד בין n.peretz (מתאים ל-RITM0092416) לבין s.katz (אין רשומה). שיעור טוב ב-"כיסוי לגיטימי מול backdoor".
- **הניגוד בין #13 ל-#397**: שני inbox rules. אחד מ-Tor ל-proton, השני מ-IP פנימי לכתובת אישית. זה מלמד discrimination.
- השהיית coverage (#551→#554) עבדה בדיוק כמתוכנן. פעולות בזמן pause/ended נדחו בהודעה נקייה (`REJECTED: action_not_allowed ... in status paused`).

## תקלות / שגיאות מערכת (כל אחת: חומרה, שחזור מדויק, פלט שקיבלת)
1. **גבוהה: ה-claim לא נאכף בשרת, claim שני דורס בשקט.** שחזור: t1b שולח `alert.claimed {event_id:"efef2ac740d53"}` ב-#344, חמש שניות אחרי ה-claim שלי ב-#341. פלט: `OK`, בלי אזהרה ובלי conflict. שתי ההסלמות (#351 ו-#357) התקבלו. אותו דבר קרה ב-#194 (ה-claims ב-#230 וב-#234, ההסלמות ב-#239 וב-#261). `projections.ts:27` פשוט מבצע `m.set` ל-claim האחרון. צריך שהשרת יחזיר `claimed_by_other` אם יש claim פעיל של משתמש אחר ולא נשלח `takeover:true`.
2. **גבוהה: השרת מקבל payloads לא תקינים מ-T1.** מה שראיתי באירועי t1b:
   - `disposition.set {"verdict":"probably_fine"}` (#23): ערך שלא קיים ב-UI.
   - `disposition.set` בלי event_id (#25).
   - `alert.claimed {event_id:"e0000deadbeef"}` (#21): מזהה שלא קיים בפיד.
   - `escalation.requested` ריק לגמרי (#146). T2 קיבל אותו והחזיר bounce עם `"event_id":"undefined"` (#164).
3. **בינונית: אפשר לענות פעמיים על כרטיס.** ב-#299 עניתי, ו-t1b ענה שוב ב-#319. השרת קיבל את שתי התשובות (t1b ציין זאת ב-#326). `InjectFeed.tsx:45` מסתיר את הכפתורים רק בצד הלקוח.
4. **בינונית: הסלמות על אותו event_id מתמזגות.** T2 כתב ב-#267 שאי אפשר להחזיר (bounce) את ההסלמה הכפולה שלי #261, כי ה-event_id כבר במצב resolved. אצלי ב-"My escalations" היא מוצגת כ-resolved בלי שאיש טיפל בה. הסטטוס מחושב לפי event_id ולא לפי seq של ההסלמה (`T1Console.tsx:86-95`).
5. **בינונית: לוגים ממוחזרים זהים עם id חדש.**
   - #577 זהה ל-#322 כולל `ts:"2026-01-01T08:16:01.432Z"` ו-`repeatcnt 127`.
   - #539 חוזר על #70: "it.admin created a user account for n.gilad", כלומר אותו חשבון נוצר פעמיים.
   - #581 חוזר על #35.
   - "svc-legacy removed from the Reporting universal group" מופיע פעמיים (#524 ו-#532).
   זה מנפח את התור ומלמד משהו לא הגיוני.
6. **נמוכה (בהארנס בלבד, לא במוצר):** `sim.ts` זורק EPIPE כשמצנררים ל-`head`.

## שגיאות מקצועיות בתוכן (לוג/שדה/ורדיקט/MITRE/תרחיש — עם feed id וציטוט השדה)
- **#8** (`ee76d3093e336`): `"dmarc=pass action=none header.from=nexacorp.com"` כש-`dkim=pass header.d=mailout-nexacorp.com` ו-`smtp.mailfrom=mailout-nexacorp.com`. זה דומיין רשום אחר, ולכן אין alignment ו-DMARC חייב לצאת **fail**. בנוסף, vendor "Microsoft 365 Unified Audit Log" לא מכיל כותרות מייל, ו-`Operation:"MessageDelivered"` אינה פעולת UAL. `ts` הוא 2026-01-01 אבל `received_0` הוא "Mon, 15 Jun 2026".
- **#13** (`ee96d33b90e70`): `it_verify_message: "...This is almost certainly a BEC/compromised account — escalate immediately."`. זה רמז מפורש בתוך הלוג. גם `forward.tor_exit` ו-`forward.destination_type` אינם שדות UAL: ב-New-InboxRule אמיתי יש מערך `Parameters` של Name/Value.
- **#60**: התיאור אומר "added ... as a guest user" (account_create), אבל `Operation:"Add member to group"`. בנוסף `hostname:"SRV-NXC-DC01"` על פעולת Entra בענן.
- **#87**: `ErrorNumber 53003` / `BlockedByConditionalAccess` מול התיאור "two-factor auth required". דרישת MFA היא 50074/50076, לא 53003.
- **#144** (`ef8e5d70f7696`):
  - `it_verify_message` מתאר את "p.wright (CTO)", אבל ב-#18 כתוב `user_title:"Legal Counsel"`.
  - חלון ה-CHG "05/10–05/11" לא תואם לתאריך הלוג.
  - `SubjectLogonId:"0x3e7"` (סשן SYSTEM) לצד `SubjectUserName:"it.admin"` ו-SID שמסתיים ב-500 זה צירוף לא עקבי.
  - **התוצאה בפועל:** ב-ground truth האירוע כנראה benign, אבל הסתירות האלה גרמו ל-TI ולי להפוך את הוורדיקט, ונענשנו על כך.
- **#194**: `severity:"critical"` לצד `is_detection:false`, בזמן ש-#166 (שלב מוקדם יותר) מסומן true. התיאור "Three seconds later…" הוא טקסט יחסי שתלוי בלוג קודם, וכותרת התראה אמיתית לא נכתבת כך.
- **#265**: `file.hash.sha256` ו-`file.name:"powershell.exe"` מוצגים כקובץ האיום. זה מזמין מלכודת: אנליסט עלול לחסום את ה-hash של powershell.exe החתום. `threat.name:"ScriptBasedDropperFromBrowserDownload"` אינו פורמט של כותרת התראה ב-MDE.
- **#237/#291/#318**: אירועי 4720/4728 לחשבון **דומיין** נרשמים על `winlog.computer_name:"WS-FIN-2847"`, תחנת עבודה ולא DC. `SubjectLogonId:"0xB17C440"` הוא סשן של WS-ENG-2093, ו-LogonId הוא פר-מכונה (TI זיהה זאת ב-#333). "Three minutes after it was created" לא מתיישב עם ה-ts (08:14:37→08:15:47 הם 70 שניות).
- **#263**: `mitre_tactic:"Initial Access"` / `T1078` ל-RDP פנימי מסוג 10. צריך להיות Lateral Movement / T1021.001. "administrative server WS-ENG-2093" עם קידומת WS סותר את מוסכמת השמות.
- **#305**: `purview.action:"block"` / `action_result:"blocked"` מול התיאור "d.brown **copied** 3,200 employee PII records". גם `dlp.bytes_copied:"7302848000"` ו-`file.path "E:\HR_Staff_Export..."` מרמזים שההעתקה הושלמה. בנוסף, CSV של 6.8GB ל-3,200 רשומות הוא כ-2MB לרשומה, וזה לא סביר.
- **#322**: `destination.ip:"10.10.1.2"` עבור SRV-NXC-DC01, בעוד שבלוגים אחרים (#60) ה-DC עם 10.10.1.5. מופיע `T1110.003` (password spraying) לחתימת "SMB-BruteForce", כשהתאים יותר T1110.001. בנוסף, זה SMB מהאינטרנט ישירות ל-DC, ושום לוג לא מתייחס לחשיפה הזו.
- **#397**: `"forward.hr_approved": "true"`, שדה ממציא שחושף את הוורדיקט.
- **#410**: `host.ip:"10.10.20.77"` ל-WS-FIN-2847, בעוד ש-#312 מציג `gp.tunnel_ip 10.10.20.14` עם `client_hostname WS-FIN-2847`. גם `event_type:"ueba_anomaly"` שגוי להתראת correlation מתוזמנת.
- **#509**: `gp.private_ip:"10.10.30.55"` הוא בדיוק ה-IP המקומי של WS-HR-1142 (ב-#47), אבל ה-VPN הוא "from home". שם ה-gateway "VPN-GW-LON-01" לא עקבי עם "gw-nexacorp-lon01".
- **#514**: vendor "Azure Activity Log" עם `operationName ...BLOBS/READ` ו-`event_category:"DataPlane"`. Activity Log לא מתעד קריאות data-plane (אלה מגיעות מ-StorageBlobLogs), ורשומה מצטברת עם `object_count 892` לא קיימת. השדה `azure.normal_work_hours` הוא רמז ממציא.
- **k8s**: באותו vendor "Kubernetes Audit" יש שתי סכמות, `kubernetes.audit.*` (#109) ו-`k8s.audit.*` (#124).
- **#209**: `source:"soar"` אבל `vendor:"ServiceNow ITSM"`, ו-`event_type:"policy_modification"` אינו מתאים ל-RITM.
- **שעונים (רוחבי)**: ה-ts תמיד 2026-01-01 08:xx, אבל התיאורים מזכירים "13:45:40", "22:47", "23:02", "20:29". כותרות המייל מ-15 ביוני, ה-CHG מתוארך למאי, ושם קובץ השכר הוא "May2026". ציר הזמן של התרחיש לא קוהרנטי.
- **ה-inject של ה-false lead** ("Marketing SaaS ... large outbound transfers ... in the firewall logs"): אין בפיד **אף** לוג כזה. סרקתי את כל 123 השורות. אי אפשר להגיע ל-discrimination מראיות. גם ל-twist ("beaconing to a NEW C2 domain") לא מצאתי לוג beacon תואם, רק את ה-stage-2 החסום ב-#240.
- **האם אפשר לגלות את התקיפה בלי רמזים?** story B ו-story C: כן, ברמה גבוהה. story A: כן, אבל ה-`it_verify_message` ב-#13 נותן את התשובה, וב-#8 התיאור כבר קובע "Return-Path is a lookalike domain".

## חיכוך בחוויית המשתמש (עם file:line מהקומפוננטה)
- `T1Console.tsx:39`: התור כולל רק high/critical. הסימנים הראשונים של story C (#263 medium, #275 low) וה-DA add ב-#144 (medium) לא נכנסים לתור, אף ש-`shared.tsx:26` מגדיר SLA של 10 דקות ל-medium. אנליסט שעובד רק מהתור יחמיץ את story C עד ל-#318.
- `projections.ts:25-28` + `T1Console.tsx:282`: המודאל דורש "Set a disposition first", ו-disposition מוחק את ה-claim. במהלך כתיבת ההסלמה נעלם סימן ה-🔒 מהרשימה הנפתחת (`:53`), ונשאר רק badge של disposed. כדאי להשאיר את ה-claim עד escalate או release.
- `T1Console.tsx:57` + `:223`: "Take over" ו-"Take this alert" שולחים בדיוק את אותו payload. השרת לא יודע להבחין בין השתלטות מודעת לבין race.
- `InjectFeed.tsx:61-62`: התשובה לכרטיס היא טקסט קבוע ("verified caller, no code shared" / "refused the request..."). אין שדה לשם המשתמש, למספר המתקשר או לשאלת "האם נמסר קוד". המנהל ביקש את הפרטים האלה (#277) ונאלצתי להשתמש ב-case note.
- `InjectFeed.tsx:16-18,59`: בקשת help-desk אמיתית ("Help desk: Marketing reports…", #228) מקבלת kind="update" ולכן אין לה כפתורי מענה. ל-T1 אין ערוץ להגיב עליה, והדוח מסמן אותה `handled:false`.
- `T2Console.tsx:186`: `evidence.pinned` קיים רק ב-UI של T2. ב-brief הוא מופיע כפעולת T1 והשרת קיבל אותו ממני (#328/#329). צריך להחליט: או להוסיף כפתור pin ל-T1, או לחסום בשרת.
- `T1Console.tsx:86-95`: "My escalations" מחושב לפי event_id. הסלמה כפולה שלי מוצגת כ-"resolved", כאילו טופלה.

## הדוח שלי (Shift review) — האם הוגן? מה חסר/שגוי?
ציון ה-rubric: 58%. Disposition accuracy 4, Escalation precision 0, Attack recall (team) 4, Card completeness 12, Handoff coordination 12, Time-to-triage 12, Backup & load-balancing 8, Self-correction null, Help-desk tickets 4. ערכי המשנה: dispAcc 67% (18/28), escQuality 100, opened 27.
- **Help-desk tickets = 4 הוא ניקוד לא הוגן.** לפי `computeReport.ts:114`, `bandHigh(ticketsAnswered,3,2,1)` סופר כמות ולא נכונות. בתרחיש היה כרטיס אחד בלבד, כך שהמקסימום האפשרי הוא 4/12. חוץ מזה, t1b שענה שני על אותו כרטיס מקבל את אותו ניקוד.
- **"suspicious" תמיד נספר כשגוי** (`computeReport.ts:272`: `isCorrectVerdict` מקבל רק true_positive או benign/false_positive). ה-UI מציג suspicious כסיווג לגיטימי של "Low-confidence lead" (`T1Console.tsx:42,293`). 4 מתוך 10 השגיאות שלי הן suspicious (#87, #144, #447, #514), וזה מעניש את בדיוק ההתנהגות הזהירה שה-UI מעודד.
- **Escalation precision = 0 הוא עונש של צוק.** `bandHigh(p,80,60,40)` נותן 0 לכל ערך מתחת ל-40%. לפי החישוב שלי כ-3 מתוך 8 ההסלמות היו "attack" (#13, #194, #318). הסלמות שמקצועית נכונות נספרו כ-0: אימות DA מחוץ לחלון, DLP PII חסום ל-insider risk, SMB ל-DC מהאינטרנט, azcopy של חוזים אחרי שעות העבודה. ועוד: ההסלמה על #144, שנבעה מהסתירות בתוכן עצמו, נענשה.
- **Self-correction = null.** התיקון שלי ב-#144 היה מ-benign ל-suspicious. לפי ground truth זה כנראה right→wrong, ולכן אין ניקוד. זה הוגן לפי המפתח, אבל התוכן (חלון CHG שפג ותפקיד סותר) הוא שהוביל לטעות.
- **הוגן**: Card completeness 12, Time-to-triage 12, Handoff 12 ו-Backup 8. כולם משקפים נכון את מה שעשיתי. גם ההחמצה של ה-false lead (`handled:false`) נכונה, אם כי לא היה לי לא לוג ולא כפתור לטפל בה.
- **חסר בכרטיס:** אין בו פירוט לפי אירוע של הסיווגים ה"שגויים", כך שאי אפשר ללמוד ממנו. אין הבחנה בין הסלמה כפולה שנבעה מ-race לבין הסלמה מיותרת. ה-case notes והתרומה ל-scoping (למשל #410 ו-WS-ENG-2208) לא נמדדים בכלל.

## 3 המלצות מובילות
1. **לאכוף claim בשרת.** להחזיר `claimed_by_other` כשיש claim פעיל של אחר, ולדרוש `takeover:true` מפורש מהכפתור "Take over". לשמור את ה-claim עד escalate/release ולא למחוק אותו ב-disposition. בנוסף להוסיף validation ל-payloads של T1: enum של verdict, event_id שקיים בפיד, הסלמה עם שדות חובה, ותשובה אחת לכל כרטיס.
2. **לנקות את התוכן:**
   - להסיר שדות שמסגירים את הוורדיקט (`it_verify_message` "escalate immediately", `forward.hr_approved`, `azure.normal_work_hours`, `forward.tor_exit`).
   - ליישר את השעונים בתיאורים ל-ts.
   - לתקן את DMARC ב-#8.
   - להעביר את 4720/4728 ל-DC.
   - לתקן MITRE ב-#263 ל-T1021.001.
   - ליישב סתירות זהות (p.wright, IP של DC01 ושל WS-FIN-2847).
   - לעצור מחזור של לוגים זהים.
   - לוודא שלכל inject שמפנה ל-"firewall logs" יש לוגים תואמים בפיד.
3. **לתקן את הוגנות ה-rubric של T1:**
   - לנקד Help-desk לפי נכונות ההחלטה.
   - לתת ל-"suspicious" ניקוד חלקי (או מלא כשזה ground truth מסוג "investigate").
   - להחליף את הצוק ב-precision בסקאלה רציפה, ולא להעניש הסלמת low-confidence שהסתיימה ב-bounce או benign.
   - להכניס medium לתור ה-T1.
   - לתת ערוץ מענה (ובמידת הצורך טקסט חופשי) גם לבקשות help-desk מסוג update.
