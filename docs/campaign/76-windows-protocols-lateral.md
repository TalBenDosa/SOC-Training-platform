# תסריט חדר 76: Windows Protocols & Lateral Movement

**שם המבצע:** Operation Side Door
**רמה:** מתקדם
**העולם:** Pinehurst Mills (יצרנית טקסטיל בדויה): שני אולמות אריגה, ארבעים שנה של דוגמאות בד על שרת קבצים אחד, וחשבון אדמין אחד שזז בלילה.
**המנטור:** Nomvula Strand, Threat Hunter. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
בין 01:00 ל-02:30 בלילה של יום ראשון החשבון adm-r.dube נגע בחמש מכונות, ושום התראה לא קפצה, כי כל צעד כזה הוא משהו ש-IT עושה כל שבוע. רק שבעל החשבון בחופשה מיום שישי. Nomvula כבר יודעים שהחשבון זז. השאלה היא באיזו דלת הוא השתמש בכל פעם, כי כל דלת משאירה צורה אחרת על המכונה שממנה יצא ועל המכונה שאליה הגיע. מאחורי הלילה הזה יש גם רקע: relay ביום חמישי דרך לפטופ זר ב-Shed 2, סריקת דיירקטורי ביום שישי, ופרץ בקשות טיקטים בשבת.

## המכניקה הייחודית של החדר
**Which Door Did They Use?** אותו חשבון אדמין עובר ב-SMB, במשימה מתוזמנת, ב-WMI, ב-WinRM וב-RDP, וכל דלת משאירה צורה אחרת במקור וביעד.
- **Which Door Did They Use?** (`deduce`): חמש דלתות על הלוח, והלומד מוחק כל דלת שלא יכלה להשאיר את הראיות. עקבה חסרה היא ראיה.
- **Find the Hop No Service Log Saw** (`hunt`): סולם KQL בן חמישה שלבים שמוצא את ה-hop ב-WinRM. ה-join קושר כל תהליך להתחברות שלו לפי המכשיר ולפי LogonId, כי LogonId ייחודי רק במכשיר אחד, וב-join בלי המכשיר שורה אחת הופכת לשתיים.
- **Chasing One Account Host by Host** (`outbreak`): הלומד מקבל בכוונה רק בידוד מארחים, ומרגיש כמה זה עולה. השיעור בסוף: חותכים credential או פרוטוקול, לא מארח.

## העולם התלת-ממדי
אי קמפוס (`facility`) של המפעל: חמישה מבנים לפי התחנות, בקשת סביב ה-Hub, בלי מבנה מאחורי מבנה ובלי מבנה מול ה-Hub. עיר ה-Hub נושאת את שם החברה.

## סדר המשימות
השאלות בחדר המקורי באות אחרי כל הקריאות, אז הסדר השתנה. הקריאות נשארו בסדר 1 עד 6, כדי שההפניות "Reading N" שבטקסט שלהן יישארו נכונות, ו-la1 קודם ל-f1 ו-la2 קודם ל-qf1.

r1 | r2, o1, r3, q2 | r4, r5, q3 | r6, q1, m1, la1, f1 | la2, qf1, ac1

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Shares | r1 | **How an SMB Session Opens** (sequence), **What Sits Behind a Hidden Share** (worksheet), **Normal Traffic or a Finding?** (sort) |
| 2 | The Tickets | r2, o1, r3, q2 | **Read a Kerberos Sign-In on the Wire** (pcap), **Which Kerberos Trick Left This?** (lineup), **Is RC4 Proof or a Hint?** (worksheet) |
| 3 | Relay and Recon | r4, r5, q3 | **Carry a Handshake Between Two Connections** (sequence), **Read an NTLM Check on the DC** (anatomy), **Would the Relay Land Here?** (sort), **Crawl or Everyday Lookup?** (sort), **What a Filter Says Comes Next** (worksheet) |
| 4 | The Doors | r6, q1, m1, la1, f1 | **Read a Named Pipe Record** (anatomy), **Install a Service From Another Machine** (sequence), **Which Door Did They Use?** (deduce), **Explained or Open?** (sort), **Find the Hop No Service Log Saw** (hunt), **Read a Service Install Record** (anatomy) |
| 5 (בוס) | Ours or Theirs | la2, qf1, ac1 | **Chasing One Account Host by Host** (outbreak), **What Does Each Cut Reach?** (sort), **Count or Distinct Count?** (worksheet), **What Does the Record Have to Prove?** (queue) |

כל primer בחדר מקופל (`fold: true`), כי זה חדר מתקדם.

**הפרדה מהשאלות הנבחנות (מה מלמד כל רעיון, ובמה זה שונה):**
- **שאלת הביניים של r1 (IPC$):** בגיליון What Sits Behind a Hidden Share העובדה מופיעה רק כשורת נתונים (ShareLocalPath ריק), ולא נשאלת. השאלות שם על ה-$, על נתיב ועל מקור.
- **f1 (הנתיב המלא):** אותו גיליון מרחיב את ADMIN$ עבור fixdrv.exe, לא PSEXESVC.exe.
- **שאלת הביניים של r2 (מפתח הטיקט):** ב-pcap העובדה מופיעה בעץ החבילה (המפתח של בעל ה-SPN), והשאלות על PA-ENC-TIMESTAMP, krbtgt, endtime ופורט. אין שם SQL ואין פיצוח.
- **o1 (סדר Kerberos):** ה-pcap מראה את הסדר בחבילות ולא מבקש אותו. השירות הוא cifs ל-PM-ARCHIVE-01.
- **q2 (Pass-the-Ticket):** ב-lineup, סבב הטיקט הוא service ticket גנוב: logon מסוג Kerberos ממארח חדש, בלי 4768 ובלי 4769 ממנו. ב-q2 יש 4769 מהמארח החדש. מיד אחריו סבב הניגוד overpass-the-hash, עם 4768 מהמארח החדש.
- **שאלת הביניים של r4 (relay):** הרצף ב-NBT-NS מול PM-PLOT-02, לא LLMNR מול שרת קבצים כללי.
- **q3 (פילטר SPN):** הפילטר הוא שורה מתויגת ב-What a Filter Says Comes Next ולא נשאל. השאלות על DONT_REQ_PREAUTH ועל adminCount, והשיטה היא "הפילטר אומר מה בא אחריו". הקשר ל-Kerberoasting מופיע בתיק של ה-lineup.
- **שאלת הביניים של r6 (מה 7045 מפספס):** בלוח הדלתות, "New service?" הוא נתון, והאשם הוא משימה מתוזמנת, לא WMI.
- **q1 (הקשר של הגישה):** Explained or Open? משתמש ב-atsvc, ב-wkssvc, ב-spoolss ובשיתופים, בלי svcctl בין תחנות עבודה. הרעיון נמצא בהסברים של הפריטים, לא ב-primer.
- **m1 (תעבורה לכל טכניקה):** הפורטים הם נתונים בעמודת Network של לוח הדלתות, ולא נשאלים. AP-REQ מופיע בחבילה 5 של ה-pcap. שום קריאה בחדר לא מלמדת WinRM ו-RDP, ולכן הם נלמדים רק כאן.
- **la1 (5145 ו-7045):** האנטומיה של 5145 על wkssvc ב-PM-ERP-02, והאנטומיה של 7045 על FixDrvSvc ב-PM-DYE-05. אין שם m.reyes, WKS-OPS31 או PSEXESVC. השלב הבא נלמד במיון של q1.
- **la2 (פרץ וקידוד):** הגיליון מראה 5 טיקטים בשש שניות, לא 47 על 44. ההבדל בין מארח, credential ופרוטוקול נלמד ב-outbreak וב-What Does Each Cut Reach?, בלי אף אפשרות של השאלה הנבחנת.
- **qf1 (חוק KQL):** התרגיל על 4768 ו-PreAuthType 0 עם `dcount`, לא על 4769 ו-RC4, ומתיק ישן באתר אחר (172.16.x), כדי שלא יסתור את רשימת ה-LDAP של החדר. התבנית של השאלה לא מופיעה.
- **ac1 (הפסק הסופי):** לתור יש מעבדה משלו על האות המכריע: מה רשומה חייבת להוכיח. ההתראות על משימה, WMI, שיתוף ו-WinRM, לא על svcctl ושירות חדש מ-jump host של Helpdesk. שם גם נלמד ההבדל בין benign true positive ל-false positive.
- **ציד ה-KQL:** מוצא WinRM ומחבר תהליכים להתחברויות, לא Kerberos ‏(qf1) ולא ההורה של WMI ‏(r6).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "No Alert Fired" | כניסה | תחנה 1 |
| Chapter 2: "A Laptop Nobody Owns" | אחרי The Tickets | תחנה 3 |
| Chapter 3: "Five Shapes" | אחרי The Doors | תחנה 5 |
| Finale: "Whose Hand" | אחרי Ours or Theirs | החדר הבא |
