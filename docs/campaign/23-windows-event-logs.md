# תסריט חדר 23: Windows Event Logs

**שם המבצע:** Operation Flight Recorder
**רמה:** בינוני
**העולם:** Morrow Bank (בנק בדוי) עם 2,000 שרתים ותחנות Windows. כל אחד מהם כותב יומן משלו כל שנייה.
**המנטורית:** Rhea Kapoor, ראש צוות DFIR.

## סיפור הרקע
כשמשהו משתבש, הצוות של Rhea שולף קודם את היומנים: מי התחבר, איך, מה רץ, והאם מישהו ניסה לתלוש דפים. כדי לקרוא את הסיפור צריך לדעת:
- כמה זמן היומן שומר.
- אילו רשומות חשובות.
- איך אירועים מתחברים לדפוסים.

## העולם התלת-ממדי: Flight Recorder
- קופסת הקלטה כתומה מגלגלת סרט של מזהי אירועים: 4624 כחול, ‏4625 צהוב, ‏4688 סגול, ‏4720 ירוק ו-4672 ורוד. בקצה הסרט נשרו רשומות ישנות, כי היומן נכתב במעגל.
- חוגה של logon types שהמחוג שלה נעצר על 9.
- עמוד w3wp.exe שצומח ממנו ענף cmd.exe.
- מניפת spray: מקור אדום יורה חצים אל חשבונות רבים. אחד מהם נדלק, וממנו קפיצה למארח שני.

## סדר המשימות
r1, q2 | r2, q1, q4 | q3 | r3, la1, flag1

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Black Box | r1, q2 | **How Far Back Does It Go?**: ‏Get-WinEvent -ListLog (‏20MB, ‏Circular), והאירוע הוותיק ביותר. היומן מכסה רק כעשר שעות אחורה |
| 2 | Who Logged On, and How | r2, q1, q4 | **The Logon Types Nobody Reads**: ‏4, ‏5, ‏7, ‏9 (seclogo, ‏pass-the-hash) ו-11. **Account Changes**: ‏4720, ‏4740 ו-4672 |
| 3 | What Ran | q3 | תרגול **Anatomy of a 4688**: ‏w3wp.exe מפעיל cmd.exe ‏(web shell) |
| 4 (בוס) | Patterns | r3, la1, flag1 | **From Spray to the Next Host**: ‏4625 לפי IP, ‏4624 שהצליח, ו-4648 אל MB-FS-03 |

**הפרדה מהשאלות הנבחנות:**
- קונסולת השמירה לא עוסקת ב-1102 (q2).
- דף ה-logon types לא כולל type 3 מתחנה (q1) ולא את RDP (q4).
- ה-4688 הוא web shell, ולא Word עם PowerShell מקודד (q3).
- ה-spray מגיע מ-198.51.100.200, ולא מ-203.0.113.45 של la1. אין בו שינוי חברות בקבוצה (flag1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Ten Hours of Memory" | כניסה | תחנה 1 |
| Chapter 2: "Type 9" | אחרי The Black Box | תחנה 2 |
| Chapter 3: "A Web Server Opens a Shell" | אחרי Who Logged On, and How | תחנה 3 |
| Finale: "From Spray to the Next Host" | אחרי הבוס | החדר הבא: Linux Log Analysis |
