# תסריט חדר 35: Wazuh Fundamentals

**שם המבצע:** Operation Open Watch
**רמה:** בינוני
**העולם:** Hexley Games (סטודיו משחקים בדוי): 300 מפתחים, 140 שרתי build של Linux, והשקת משחק בעוד שישה שבועות שחצי מהאינטרנט רוצה להדליף.
**המנטור:** Lucía Ferrer, מהנדסת SIEM.

## סיפור הרקע
אין תקציב ל-SIEM מסחרי, אז Hexley מריצה Wazuh: קוד פתוח, agent על כל שרת, ו-manager שמחליט מה שווה התראה. Lucía בנתה את המערכת. הלילה מחסן הנכסים (art-store-02) השתתק, ושרת ההפצה של המשחק שינה קובץ הגדרות. היא רוצה אנליסט שמבין מה קורה בין שורת לוג בשרת לבין התראה בדשבורד.

## העולם התלת-ממדי: Open Watch
- טבעת של agents שמזרימים חבילות אל ליבת ה-manager. אחד מהם כבוי ואחד מעולם לא נדלק.
- גלגל decoder שמפרק כל חבילה לשדות שנופלים דרך מסננת של שלוש רמות (0-6, ‏7-11, ‏12-15).
- כספת sshd_config עם עין FIM שפועמת.
- משואת התראה שעולה מעל הליבה.
- טבעת שסוגרת את כל הצינור.

## סדר המשימות
r1 | r2, q1 | r3 | la1, flag1 | q2, q3 (זהה למקור. התחנות פשוט מקבצות אותו)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Agents and Manager | r1 | **Roll Call**: ‏agent_control -l (agent מנותק ו-agent שמעולם לא התחבר) ו-ss לפורט ההרשמה 1515 |
| 2 | Decoders and Rules | r2, q1 | **Through the Logtest**: ‏wazuh-logtest על כישלון sshd: ה-decoder, ‏srcip ו-dstuser |
| 3 | FIM and SCA | r3 | **Who Changed That File?**: התראת 550 על sshd_config ‏(PermitRootLogin), ‏whodata שחושף את j.marsh, וציון CIS |
| 4 | The New User | la1, flag1 | ההתראה הנבחנת |
| 5 (בוס) | Close the Loop | q2, q3 | מה קורה אחרי הפענוח, ותגובה אוטומטית |

**הפרדה מהשאלות הנבחנות:**
- קונסולת ה-manager שואלת על הרשמה ועל agent שהשתתק, ולא על פורט האירועים (checkpoint של r1).
- ה-logtest לא שואל על רצועת רמות (q1) ולא על טווח rule-ID ‏(flag1).
- ה-FIM שומר על sshd_config, ולא על /etc/passwd או /etc/sudoers ‏(la1).
- שום תרגול לא מגדיר חסימה אוטומטית (q3).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Six Weeks to Launch" | כניסה | תחנה 1 |
| Chapter 2: "From Line to Alert" | אחרי Decoders and Rules | תחנה 3 |
| Chapter 3: "PermitRootLogin yes" | אחרי FIM and SCA | תחנה 4 |
| Finale: "The Whole Pipe" | אחרי הבוס | החדר הבא: Microsoft Sentinel |
