# Hack The SOC — אבחון מקצועי לתרגיל צוותי
 · 

## תקציר מנהלים
הפלטפורמה חזקה מאוד במבנה ובפורמטים, אבל יש פער מהותי באמינות הלוגים ובקוהרנטיות שרשרת התקיפה. ציון כולל מקצועי: 7/10. בדקתי 81 לוגים בפיד (8 מהם תקיפה), כ‑20 מהם ברמת raw, ואת ה‑Shift Review המלא.
מה עובד מצוין: סכמות Native של Entra ID, MDE Streaming API, Office 365 UAL, Palo Alto THREAT, Sysmon 13/22 ו‑auditd USER_CMD (כולל cmd מקודד hex) — ברמה שאנליסט ותיק יזהה כאמיתית. רעש מתוכנן היטב עם "מלכודות" לגיטימיות (certutil עם טיקט, rclone, Amplitude), דיבריף No-fault ו‑MSEL.
5 הממצאים הקריטיים:

Windows Event XML שבור: EventID/Provider/Channel לא תואמים (4688 בערוץ TaskScheduler עם EventData ריק; 4624 תחת TerminalServices-LocalSessionManager; 4625 בלי TargetUserName ו‑LogonType).

Key Vault נרשם כ‑Activity Log ולא כ‑AuditEvent — בדיוק בלוג שהוא שיא התרחיש, ועם Resource ID שונה לאותו Vault בשני לוגים.

פערים בשרשרת התקיפה: מייל פישינג עם UrlCount=0 ו‑AttachmentCount=0, ו‑DLL על התחנה בלי וקטור הגעה. שם התרחיש "Secrets Exfil" אבל יש רק secrets/list.

התיאור בפיד חושף את הפתרון ("CapsLock on", "Office update", "service restart needed", "DKIM and DMARC failed") — הורס את אימון ה‑triage.

אין למדריך תצוגה של קונסולת כל תפקיד, ותרגיל עם שחקן אחד נועל את Attack 2/3 ומשאיר את כל ה‑injects של המנהל ללא מענה.

## הגדרת התרגיל ומגבלות הבדיקה
התרגיל רץ 35 דקות חיות (09:30–10:07), מסונכרן לשעון הדפדפן ב‑UTC+3.

פרמטר
ערך
ארגון
meridian-logistics.io (NetBIOS: MERIDIANLOGISTI)
קושי
Medium
תרחיש ראשי
Phishing → Inbox Rule → Key Vault Secrets Exfil (7 שלבים)
תקיפה עצמאית
Impossible travel — e.petrov (לוג 1)
מוצרים
MDE, Palo Alto, GlobalProtect, Entra ID, M365, MDO, Windows DNS + Azure, Linux
נפח
81 לוגים, 15 מקורות, 7 injects
צוות
TES — Tier-1; אני — Instructor
מגבלות שהשפיעו על הבדיקה:

בחרת 3 התקפות, אבל עם שחקן אחד המערכת נועלת את Attack 2/3 (הנוסחה: עד 2 שחקנים = סיפור אחד).

משתמש יכול להחזיק תפקיד אחד, ולמדריך אין "תצוגה כ‑". לכן חוויית התפקידים נותחה מתוך מסך המדריך, קוד הדף (טקסטים, מדדים, רובריקות) וה‑Shift Review — לא "מהכיסא" של T2/T3/Manager.

TES לא ביצע פעולות, כך שהדיבריף מציג מצב "צוות שלא פעל" — שימושי דווקא לבדיקת הניקוד.

## דוח לפי תפקיד
מודל התפקידים נכון מקצועית ומשקף SOC אמיתי (T1 → T2 → T3 → Manager על Shared Case אחד). הבעיות הן בעיקר בתוכן שכל תפקיד מקבל ובמדידה.

תפקיד
חוויית משתמש
חוויה מקצועית
תוכן
ציון
Tier-1 Triage
8/10
6/10
6/10
6.5
Tier-2 Investigator
7/10
6/10
5/10
6
Tier-3 / Threat Hunter
6/10
5/10
5/10
5.5
SOC Manager
7/10
7/10
6/10
6.5
Instructor
6/10
8/10
—
7

### Tier-1 Triage
חוויית משתמש — טוב: טבלת פיד בסגנון SIEM, מסנני מקור וחומרה, תצוגת Analysis/Raw, כפתורי pivot, תגית SLA ("needs triage · 28m · unclaimed") ו‑SOC Analysis Guide בחמישה שלבים.
חוויית משתמש — לתיקון:

הטבלה גולשת אופקית ועמודת Time נחתכת כשפותחים לוג ארוך.

שעון הפיד מוצג בשעון הדפדפן (09:30) בלי סימון אזור זמן, כשה‑raw ב‑UTC (06:30Z) והארגון בלונדון.

עמודת Source מוצגת כ‑"ACTIVE DIRECTORY" כשה‑Analysis אומר event.provider=Windows Security, ו‑"OFFICE 365" כשה‑Raw מסומן "Microsoft Entra ID — Native JSON".
חוויה מקצועית: הדילמה הנכונה קיימת — benign מותנה (certutil + INC-44821, rclone 11GB) מול תקיפה. אבל התיאורים נותנים את הפסק: "Microsoft Office update wrote", "Windows Update installed", "Normal POST", "service restart needed", "for maintenance". אנליסט לא צריך לפתוח raw כדי לסגור. במקביל, התקיפה עצמה מסומנת במפורש ("DKIM and DMARC failed", "to an external address").
תוכן: ה‑ticket (קריאת קוד MFA בטלפון) מצוין ורלוונטי. חסר קשר בין ה‑ticket לטלמטריה (אין לוג של השיחה או של ניסיון MFA).

### Tier-2 Investigator
חוויית משתמש: Inbox הסלמות, דוח מובנה (Summary / Findings / Recommendations), בקשת Containment עם trade-off, מסוף EDR נפרד. כוונת "Investigate in EDR" פותחת pop-up — נחסם על ידי דפדפנים רבים (הקוד כבר מצפה לזה).
חוויה מקצועית — חסמים בחקירה:

אי אפשר לשייך את הקצה למשתמש: בלוג ה‑rundll32 שדה InitiatingProcessAccountName=null, וב‑Sysmon 22 User="-".

אין SenderIPv4 במייל, אין URL ואין קובץ — אין מה לעשות ל‑pivot מהמייל לתחנה.

אין לוג יצירת קובץ של svcmgr252.dll ואין תהליך אב מעבר ל‑explorer.exe.
תוכן: עשיר במחקר אבל לא עקבי — ראו סעיף השרשרת.

### Tier-3 / Threat Hunter
חוויית משתמש: הפיצ'ר החזק ביותר — כתיבת כלל מבוסס שדות (source · host · user · ip · mitre · rule · vendor · event · severity) עם back-test חי על הפיד. מוגבל ל‑AND בלבד — אין OR, NOT, סף, חלון זמן או ספירה.
חוויה מקצועית: עם 81 לוגים ב‑ 35 דקות אין מספיק נפח לציד אמיתי (beaconing מחייב עשרות חיבורים מחזוריים; יש שניים). לא ניתן לאמת את ה‑impossible travel — יש רק פסק UEBA, בלי שתי רשומות SigninLogs מתל אביב ולאגוס.
תוכן: ה‑Twist מבקש re-scope בגלל "NEW C2 domain" — אבל לא הופיע בפיד שום דומיין חדש. הצייד נשלח לחפש משהו שלא קיים.

### SOC Manager
חוויית משתמש: אישור/דחיית Containment עם סיבה, חסימה עדינה אם אין דוח T2, SITREP, Passdown ואזהרת span of control (~7). זה הרבה מעל המקובל.
חוויה מקצועית: ה‑injects מצוינים (CISO, Legal, Exec) ונכונים לתפקיד. אבל ה‑CISO inject נורה באירוע #23, לפני לוג התקיפה הראשון (#33): בקשת סטטוס על "suspicious activity" שעדיין לא קיימת.
תוכן: ה‑Legal inject מצוין לאור ה‑Key Vault, אבל בלי פרטי סוגי הסודות (רק "12 secrets") המנהל לא יכול להעריך חשיפת מידע אישי / חובת דיווח.

### Instructor

אין תצוגה של קונסולת תפקיד (View as T1/T2/T3/Manager).

מצב Ready של השחקן לא התעדכן בזמן אמת ("Reconnecting") — הצריך רענון.

סיום סשן והסרת שחקן משתמשים ב‑confirm() של הדפדפן.

Threat Intel ו‑Observer קיימים ב‑Reassign אבל לא במסך ההזמנה; Detection Engineer קיים בקוד אבל לא ניתן לבחירה. האזהרה מזכירה "SOC Manager or Lead" — תפקיד Lead לא קיים.

בחלון "how my role works" של Instructor השדה "You're measured on" ריק ("• —").

ה‑Answer key של המדריך מצוין: לוגי תקיפה לפי אירוע, expected לכל inject, מצב בזמן אמת.

## בדיקת לוגים מול Data Source
מתוך 20 לוגים שנבדקו ב‑raw: 9 תואמים את המקור ברמה גבוהה, 6 עם סטיות קלות, 5 שבורים מהותית. כל שורת Windows XML שבדקתי הייתה בעייתית; JSON של מייקרוסופט כמעט תמיד מצוין.

לוג (שעה)
מקור מוצג / פורמט
פסק
הערה מקצועית
ScheduledDefrag on DC01 (09:36)
Windows Security / Event XML
שבור
EventID 4688 עם Provider=Security-Auditing אבל Channel=TaskScheduler/Operational, ו‑EventData ריק. הרצת משימה היא TaskScheduler 200/201 או 4688 עם NewProcessName ו‑CommandLine.
RDP session on DC01 (09:34)
Active Directory / Event XML
שבור
Provider TerminalServices-LocalSessionManager עם EventID 4624 ו‑Keywords של Audit Success. LSM משתמש ב‑21/22/25 וב‑UserData; RDP ב‑Security הוא 4624 LogonType 10.
Failed unlock (CapsLock on) (09:33)
Active Directory / Event XML
שבור
חסרים TargetUserName ו‑LogonType. SubStatus 0xC0000234 + %%2307 = חשבון נעול, לא סיסמה שגויה (0xC000006A). Unlock מקומי = LogonType 7 מ‑127.0.0.1, לא NTLM מ‑IP מרוחק. Windows לא רושם CapsLock.
Listed 12 secrets (09:56)
CLOUD_AZURE / Activity Log
שבור
secrets/list הוא data plane — לא מופיע ב‑Activity Log. הפורמט הנכון: AzureDiagnostics/AuditEvent, operationName=SecretList, callerIpAddress, identity.claim.appid/oid. Resource ID עם MICROSOFT.RESOURCES וללא /VAULTS/.
CI pipeline read DB password (09:39)
CLOUD_AZURE / Activity Log
שבור
אותה בעיה (SecretGet). Resource Group שונה מהלוג הקודם לאותו Vault (RG-MERIDIAN-LOGISTICS-PROD מול RG-PROD). Service principal מופיע עם UPN — ל-SP אין UPN.
f.walsh network logon (09:30)
Active Directory / 4624
סטיה
ב‑LogonType 3 ה‑Subject הוא NULL SID (S-1-0-0) ו‑ProcessId 0x0, לא SYSTEM/0x4. Version 0 במקום 2 (חסרים ImpersonationLevel, ElevatedToken, LogonGuid). Execution ProcessID=4 במקום PID של lsass.
כל לוגי Windows XML
—
סטיה
Task=0 תמיד, שדות בסדר אלפביתי, TimeCreated ב‑6 ספרות + "+00:00" (במקור 7 ספרות + Z). Domain SID של f.walsh שונה מזה של it.admin באותו דומיין.
Phishing email to g.silva (09:43)
Office 365 / MDO EmailEvents
סטיה
סכמה מצוינת, אבל UrlCount=0, AttachmentCount=0, SenderIPv4 ריק. CompAuth=fail עם Delivered/No action בלי הסבר (override?). דומיין lookalike של התוקף בדרך כלל עובר DKIM/DMARC.
g.silva sign-in Amsterdam (09:47)
Office 365 / Entra SigninLogs
סטיה
appId של OfficeHome אמיתי. אבל ASN 9009 (M247) לא תואם ל‑185.220.100.x (טווח Tor exit של F3 Netze/Zwiebelfreunde — לא M247). riskLevelDuringSignIn=none מ‑Tor exit — Identity Protection היה מסמן anonymizedIPAddress. מדיניות CA שונה מהלוג של g.ahmed.
UEBA e.petrov (09:46)
UEBA / “Microsoft Sentinel UEBA”
סטיה
סכמת ECS מומצאת (ueba.*). ב‑Sentinel זו טבלת BehaviorAnalytics (ActivityInsights, InvestigationPriority). Sentinel לא נבחר כמוצר. אין SigninLogs תומכים.
Proxy to app.intercom.io (09:33)
Proxy / Zscaler NSS
סטיה
פורמט טוב, אבל Zscaler לא נבחר במוצרים. IP-ים מטווח תיעוד (203.0.113.x, 192.0.2.x) — העשרה (WHOIS/TI) תיכשל.
rundll32 → 193.42.33.18 (09:53)
EDR / MDE DeviceNetworkEvents
תקין
סכמה מצוינת. חסר InitiatingProcessAccountName. נתיב C:\Users\Public\AppData\Local\Temp לא קיים ברירת מחדל.
certutil -decode (09:42)
EDR / MDE DeviceProcessEvents
תקין
מצוין, כולל TokenElevation ו‑IntegrityLevel. התיאור מסגיר את מספר הטיקט.
New-InboxRule (09:52)
Office 365 / UAL
תקין
RecordType 1, ClientIP עם פורט, OriginatingServer — מצוין. חסר פרמטר Name=SyncRule01 שמופיע בתיאור.
Palo Alto URL to img-cdn (09:52)
Firewall / PAN-OS THREAT,url
תקין
CSV מלא ונכון. URL category computer-and-internet-info לדומיין C2 — סביר.
Sysmon 22 img-cdn (09:52)
Sysmon
תקין
QueryResults בפורמט ::ffff: נכון. User="-".
Sysmon 13 Office registry (09:34)
Sysmon
תקין
מדויק (OfficeClickToRun, InstallRoot\Path).
auditd USER_CMD nginx (09:35)
Linux auditd
תקין
cmd מקודד hex ו‑epoch תואם לשעה — מצוין.
GitHub MFA push g.ahmed (09:32)
Office 365 / Entra SigninLogs
תקין
מקור צריך להיות Entra ID. “Authenticator App” במקום “Mobile app notification”.
דפוסים רוחביים:

מקורות שלא נבחרו בהגדרות מופיעים בפיד: Zscaler, F5 WAF, DAM, Sentinel UEBA, SOAR/ServiceNow.

הארגון בלונדון (London-HQ), אבל יש svc-tradingapp עם "positions-report" ו‑SRV-MER-RISK01 — שארית מתבנית פיננסית (NexaCorp) בחברת לוגיסטיקה.

שמות שרתים לא עקביים: SRV-MER-*, srv-linux-app01, MERIDIANLOGISTI-SQL01. WS-FIN-2847 משמש גם את e.petrov וגם את j.zimmer.

שורות רעש חוזרות זהות ב‑ 35 דקות (r.avraham enabled ×2, rclone ×2, w.mendes ×2, intercom ×2).

קצב קבוע של 25–35 שניות בין לוגים — מסגיר סינתטיות. במציאות יש bursts.

אותו Rule ID (HTS-18101.1) ל‑ 4624, 4769, RDP ו‑GPO — מקשה ללמד tuning.

## קוהרנטיות שרשרת התקיפה
כל 7 השלבים של org-chain-a קשורים לתקיפה ומשתמשים במזהים עקביים (אותו IP 185.220.100.209 בכניסה, ב‑inbox rule וב‑Key Vault; אותו ObjectId של g.silva ב‑MDO וב‑UAL). אבל בשרשרת חסרות חוליות שאנליסט אמור לחבר.

זמן משמרת
שלב
מה חסר כדי שהשרשרת תהיה אמיתית
13:51
מייל פישינג ל‑g.silva
אין URL ואין קובץ. נדרשים EmailUrlInfo + UrlClickEvents (Safe Links) שמוכיחים קליק.
16:18
Impossible travel — e.petrov
תקיפה נפרדת — בסדר. חסרות שתי רשומות SigninLogs. הסיסמה השתנתה ב‑ 24:00 — האם זה התוקף או המשתמש? לא מוגדר.
17:48
כניסת g.silva מאמסטרדם
בלי MFA ובלי סיכון, בעוד g.ahmed מקבל "Require MFA - All users". צריך להסביר מדוע (חריגה, legacy auth, AiTM token).
22:20–23:45
DNS → FW → rundll32 C2 ב‑WS-HR-1182
אין וקטור הגעה לתחנה: אין הורדה, אין FileCreated, אין תהליך הרצה. פישינג הוא credential phishing, לא malware.
22:45
Inbox rule עם wire/payment → proton.me
זו טקטיקת BEC פיננסית אצל משתמשת HR. סביר, אבל לא מקדמת את מטרת התרחיש (Key Vault).
26:46
g.silva מריצה list על kv-...-prod
למשתמשת HR אין סיבה להחזיק הרשאה ל‑Vault פרודקשן. חסר לוג RoleAssignment שמסביר את זה (או שזה הממצא עצמו). חסר SecretGet — בלעדיו אין exfil.
פערי זמן והתנהגות:

ה‑Firewall רואה את החיבור ל‑C2 ב‑09:52:57, וה‑EDR ב‑09:53:43 — 46 שניות פער לאותו חיבור ללא הסבר.

ה‑Twist הודיע על "NEW C2 domain" אבל לא נורה שום לוג שתומך בזה.

שלב אחד בלבד לכל פעולת תקיפה — אין beaconing מחזורי, אין MailItemsAccessed אחרי הכניסה, אין ספירת הרשאות ב‑Azure.
מה מצוין: נתוני דומיין lookalike סבירים, IP של Tor exit אמיתי מהסוג שנראה בשטח, סדר DNS → FW → EDR נכון, ו‑decoy של Amplitude מוכן מראש ב‑SOAR (אישור ServiceNow).

## Injects, ניקוד ומדדים
שכבת ה‑MSEL והדיבריף היא מהחזקות של הפלטפורמה; שלושה כללי מדידה מעוותים את התמונה.
תקלות בניקוד:

ה‑Decoy סומן "REJECTED" ונספר כ‑handled במשמרת שבה אף אחד לא עשה כלום ("Curveballs 1/6 handled"). חוסר פעולה מתוגמל. נדרש: תשובה מפורשת למנהל השיווק או disposition של Benign על לוגי Amplitude.

MTTD נמדד מתחילת המשמרת ולא מרגע שלוג התקיפה הראשון נחת. כאן התקיפה התחילה ב‑ 13:51 — כל צוות מקבל 14 דקות "עונש" שלא באשמתו, והשוואה בין תרגילים לא הוגנת.

Injects של מנהל נספרים MISSED כשאין מנהל בצוות. המערכת יודעת שאין מנהל (היא מציגה אזהרה), אז יש לדלג עליהם או להעביר לשחקן הבכיר.
תזמון Injects:

CISO inject נורה לפני שהיה שום לוג תקיפה. עדיף לתזמן injects יחסית לשלבי הסיפור (למשל +5 דק' אחרי שלב 2), לא לשעון קיר.

כל 7 ה‑injects נורו במשוך כ‑ 30 דקות — עומס של בערך אחד כל 4 דקות על צוות קטן.

"due at 9:38 (shift clock)" נראה כמו שעה בפיד (09:38). עדיף "T+09:38".
מה מצוין: רובריקה 0/4/8/12 שקופה, כלל "פחות משני קריטריונים = אין ציון", ניקוד לפי תקרית ולא לפי לוג, זיהוי פסקים מנוגדים (Contested), מדדי MTTC/MTTR ו‑Handoff loop closure, ומבנה Hot-wash בארבעה שלבים.
הערות קטנות: באותו מסך מופיע "first seen 831s" וגם "13m 51s" — לאחד פורמט. הבאנר "Exercise starting…" נשאר בראש ה‑Shift Review.

## UX ופלטפורמה
הזרימה מיצירת תרגיל עד דיבריף עובדת קצה לקצה; הבעיות נמצאות במעברים ובמצבי קצה.

מסך
ממצא
חומרה
תרגיל חדש
Attack 2/3 נעולים לפי גודל צוות בלי הסבר מתי ייפתחו
בינונית
תרגיל חדש
קפיצת תצוגה (פס שחור בראש הדף) בפתיחת Environment
נמוכה
תרגיל חדש
קישור Shift review של סשן סגור לא ניווט בקליק ראשון
בינונית
לובי
Ready של שחקן לא מתעדכן עד רענון ("Reconnecting")
גבוהה
לובי
אזהרה על חוסר מנהל מופיעה, אבל ניתן להתחיל — ואז שלושה injects מובטחים להיכשל
בינונית
תרגיל חי
End session / Remove ב‑confirm() מקורי — חוסם את הלשונית ואוטומציה
בינונית
תרגיל חי
כפתור "? Guide" לא פתח דבר בלחיצה
נמוכה
תרגיל חי
טבלת הפיד גולשת אופקית; עמודת Time נחתכת
בינונית
תרגיל חי
שעון ללא אזור זמן; תצוגה מקומית מול UTC ב‑raw
בינונית
תרגיל חי
Team activity בלי חותמות זמן
נמוכה
Shift review
באנר "Exercise starting…" בראש דף הסיכום
נמוכה
כללי
אין "View as role" למדריך
גבוהה
אבטחה
ה‑answer key (expected_action) נמשך ישירות מ‑Supabase בצד לקוח. יש לוודא ש‑RLS חוסם שחקנים מלשלוף אותו (ואת סימון לוגי התקיפה). לא נבדק מצד שחקן.
גבוהה (לאימות)

## המלצות מתועדפות
העדיפות הראשונה היא שכבת הולידציה של הלוגים: אנליסט שרואה אירוע Windows שבור אחד מפסיק לסמוך על כל השאר.
P0 — לפני התרגיל הבא עם סטודנטים:

להוסיף ולידציה לכל לוג Windows: טבלת מיפוי EventID → Provider → Channel → שדות חובה (4624, 4625, 4688, 4769, 4767, 7045, LSM 21, TaskScheduler 200/201). לוג שלא עובר — לא משודר.

להעביר את לוגי Key Vault ל‑AuditEvent (SecretList / SecretGet) ולקבע Resource ID אחד לכל Vault לאורך כל התרגיל.

להשלים את השרשרת: URL במייל + UrlClickEvents, ווקטור הגעה ל‑DLL, ו‑SecretGet אחד לפחות כדי שיהיה exfil.

לנקות תיאורים מפסקים: תיאור רק מה שהמוצר היה אומר (rule.description אמיתי). בלי CapsLock, בלי "update", בלי "for maintenance".

ה‑Twist: לירות לוג של הדומיין החדש באותו רגע.

לוודא RLS על session_injects ועל סימון התקיפה ב‑session_events.
P1 — אמינות מקצועית:

עקביות ארגונית של ישויות: Domain SID אחד, סט CA אחד לכל הכניסות, משתמש ראשי לכל תחנה, תבנית שמות שרתים אחת.

רק מקורות שנבחרו ב‑Security products (או להוסיף למסך את Proxy, WAF, DAM, UEBA). להסיר תוכן פיננסי מארגון לוגיסטי.

עמודת Source = שם המוצר האמיתי (Windows Security, Entra ID), זהה ב‑Feed, Analysis ו‑Raw.

לעבור מ‑IP של טווחי תיעוד ל‑IP מציאותיים עם ASN תואם, ולסמן Tor/anonymizer ב‑riskEventTypes.

SigninLogs אמיתיים מאחורי כל התראת UEBA והבהרה מה קרה עם שינוי הסיסמה של e.petrov.

רעש עם bursts ובלי העתקות זהות; beaconing עם מספר חיבורים מחזוריים (מרווח + jitter) שהצייד יכול למצוא.
P2 — מוצר ו‑UX:

View as role למדריך, ומצב תרגול סולו שבו משתמש אחד עובר בין תפקידים.

מודאל פנימי במקום confirm(), עדכון Ready בזמן אמת, שעון עם אזור זמן, טבלה ללא גלילה אופקית.

ניקוד: Decoy דורש פעולה מפורשת, MTTD מלוג התקיפה הראשון, injects של תפקיד חסר מועברים או מוחרגים.

Injects מעוגנים לשלבי התקיפה; פורמט "T+mm:ss".

להציג במסך ההזמנה את Threat Intel ו‑Detection Engineer, ולתקן את "Manager or Lead".