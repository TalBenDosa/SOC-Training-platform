# תסריט חדר 5: Windows Fundamentals for SOC Analysts

**שם המבצע:** Operation Clean Host
**רמה:** מתחילים
**העולם:** Corvane Logistics (חברה בדויה), תחנת העבודה CVN-WS-0418.
**המנטורית:** Nadia Rahman, Endpoint Security Lead. Sam Whitlock (Incident Responder) מופיע בשאלות.

## סיפור הרקע
תחנת עבודה מתנהגת מוזר מיום שני. Nadia נותנת לך קונסולה על המחשב והוראה אחת: למצוא כל מה שלא שייך. חשבונות, תיקיות, רישום, שירותים ותהליכים, וכל אחד מהם יכול להסתיר פורץ. החדר כולו הוא חקירה של המחשב עצמו מתוך הקונסולות שלו.

## העולם התלת-ממדי: Host Core
בתוך מחשב Windows אחד: ליבת קרנל (Ring 0) בתוך טבעת User Space (Ring 3). סביב הליבה יש אזור לכל תחנה:
1. אריחי תיקיות.
2. כוורת רישום, שבה תא ה-Run מאדים.
3. עץ תהליכים, שבו ענף מתחזה נכנס להסגר.
4. קונסולת PowerShell.
5. שרשרת המאקרו (WINWORD אל powershell), שננעלת בכלוב.

## סדר המשימות
סודר מחדש לפי נושא: r1 | r2, q2 | r3, q1, q3 | r4 | la1, f1.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Machine | r1 | **Where Does It Live?**: מיקום תקין מול חשוד. כולל explorer.exe ב-System32 שהוא מזויף, ו-Defender שבאמת רץ מ-ProgramData. **Who Has Power Here?**: קונסולת cmd עם whoami /groups (רמת שלמות Medium, כלומר UAC), net localgroup administrators (החשבון svc_update2), ו-net user administrator (חשבון שהופעל מחדש) |
| 2 | Persistence Hunt | r2, q2 | **Query the Registry**: reg query על מפתחות Run של HKLM ו-HKCU, ו-sc qc/query על שירות שהושתל. **Know the Hives** (התאמה) |
| 3 | Process Patrol | r3, q1, q3 | **Process Triage**: שישה תהליכים אמיתיים או מתחזים, כולל OneDrive לגיטימי מ-AppData. **Admin or Attacker?**: שורות פקודה של LOLBins. **Decode It**: פענוח פקודה מקודדת ב-PowerShell |
| 4 | PowerShell for Defenders | r4 | **Hunt with PowerShell**: Get-Process, Get-Service (Defender עצור), Get-WinEvent 7045 (שירות שהותקן ב-02:17), Get-ChildItem על AppData |
| 5 (בוס) | The Macro Alert | la1, f1 | תרגול **Anatomy of a Process-Creation Event** על אירוע Sysmon 1 (certutil שהופעל מ-cmd), ואז ההתראה הנבחנת והדגל |

**הפרדה מהשאלות הנבחנות:**
- אין lsass.exe בתיקיית משתמש (q1).
- המעבדה לא שואלת איזה hive לא דורש הרשאות מנהל (q2).
- השירות המתחזה נמצא ב-Users\Public ולא svchost ב-ProgramData (q3).
- התרגול הוא certutil תחת cmd, ולא Word שמפעיל PowerShell (la1, f1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Something Does Not Belong" | כניסה | תחנה 1 |
| Chapter 2: "Survives Every Reboot" | אחרי Persistence Hunt | תחנה 3 |
| Chapter 3: "Impostors" | אחרי Process Patrol | תחנה 4 |
| Finale: "Host Clean" | אחרי הבוס | החדר הבא: Linux Fundamentals |
