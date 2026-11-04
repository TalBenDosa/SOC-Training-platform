# תסריט חדר 31: PowerShell for the SOC Analyst

**שם המבצע:** Operation Same Shell
**רמה:** בינוני
**העולם:** Corrin Foods (חברת מזון בדויה): ארבע מאפיות, שני מחסני קירור ו-900 מחשבי Windows שמחזיקים את התנורים והמשאיות בזמנים.
**המנטור:** Tomás Ibarra, אנליסט SOC בכיר (Tier 2).

## סיפור הרקע
כל שבוע ה-SOC של Corrin Foods רואה PowerShell שמופעל נגדו: פקודות מקודדות, חלונות מוסתרים, הורדות משום מקום. Tomás חוקר עם אותו shell בדיוק, ורוצה שגם אתה תעשה את זה. בלילה שבין 3 ל-4 בנובמבר מחשב בקרת התנור OVEN-CTL-02 התחיל להתנהג מוזר.

## העולם התלת-ממדי: Object Pipe
- שתי קונסולות (ANALYST ו-ATTACKER) שמריצות את אותו powershell.exe.
- צינור זכוכית עם שלוש טבעות (WHERE, ‏SELECT, ‏SORT): פחות קוביות-אובייקט שורדות כל טבעת, והאחרונות נערמות לגיליון CSV.
- שמות ה-cmdlets מעל הצינור.
- קרן PID שיורדת מהתראה.
- כרטיס משימה מתוזמנת שטבעת ציד נסגרת סביבו.

## סדר המשימות
r1 | r2 | r3, q1, q2 | q3, qf1 | la1, match1, flag1 (זהה למקור. התחנות פשוט מקבצות אותו)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Same Binary | r1 | **Who's at the Keyboard?**: שש הרצות של cmdlets רגילים, וממיינים לפי הקשר (הורה, חלון, משתמש, שעה) |
| 2 | The Pipeline | r2 | **Build the Pipeline**: ‏Get-Process, ואז Where, ‏Select (כולל Path), ‏Sort ו-Export-Csv, צעד אחר צעד |
| 3 | Seven Cmdlets | r3, q1, q2 | **Interrogate the Host**: ‏Get-Service (‏WinDefend כבוי), ‏Get-ChildItem, ‏Get-FileHash ו-Get-WinEvent ‏(4625 ואחריו 4624) |
| 4 | Follow the PID | q3, qf1 | **From PID to Binary**: ‏PID שה-EDR כבר נתן, ‏Get-Process -Id, ‏Win32_Process (הורה ושורת פקודה) ו-Get-AuthenticodeSignature |
| 5 (בוס) | The Task Nobody Knows | la1, match1, flag1 | **Sweep the Depot**: פלט Get-ScheduledTask, ומשימה של קבלן חיצוני שמריצה VBScript |

**הפרדה מהשאלות הנבחנות:**
- הקונסולות לא שואלות מה עמודת CPU מודדת (q1).
- הקונסולות לא מריצות Get-LocalGroupMember ‏(q2) ולא Get-NetTCPConnection ‏(q3, ‏qf1).
- ה-PID מגיע מה-EDR ולא מ-OwningProcess (‏qf1).
- הסקירה היא של משימה בתיקיית השורש, ולא משימה בתוך \Microsoft\Windows\ ‏(la1). היא גם לא שואלת מה לאסוף לפני ההסרה (la1).
- הסקריפט בסקירה הוא לא upd.ps1 ‏(flag1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Same Shell" | כניסה | תחנה 1 |
| Chapter 2: "Objects, Not Text" | אחרי The Pipeline | תחנה 3 |
| Chapter 3: "PID 6120" | אחרי Seven Cmdlets | תחנה 4 |
| Finale: "Collect, Then Remove" | אחרי הבוס | החדר הבא: Windows Privilege Escalation |
