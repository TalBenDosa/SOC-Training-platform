# תסריט חדר 25: SIEM Fundamentals

**שם המבצע:** Operation Control Tower
**רמה:** בינוני
**העולם:** Northcross Airports (מפעילת שדות תעופה בדויה): שלושה טרמינלים, ‏40,000 מכשירים, ו-1.2 מיליארד אירועי לוג ביום שזורמים אל SIEM אחד.
**המנטורית:** Sofia Marín, מהנדסת SIEM.

## סיפור הרקע
Sofia מפעילה את ה-SIEM כמו שמגדל הפיקוח מפעיל את השמיים:
- כל מקור לוגים מופיע על המכ"ם.
- חוקים עוקבים אחרי מסלולי התנגשות.
- אנליסטים יכולים לשאול אותו כל שאלה.

SIEM טוב רק כמו החוקים שלו, הכיוונון שלו והאנשים ששואלים אותו.

## העולם התלת-ממדי: Control Tower
- שולחן מכ"ם עגול עם זרוע סריקה. ‏blips זורמים אליו משישה מגדלי מקור: FW, ‏EDR, ‏IdP, ‏DNS, ‏BAGGAGE ו-CLOUD.
- חוטי קורלציה קושרים blips ומדליקים משואת התראה.
- מגלש התראות מפיל כרטיסים לשלושה סלים, TP, ‏BTP ו-FP. לידם ערימת עייפות שמתכווצת כשהתחנה נפתרת.
- כרטיס התראה מרחף לקריאה.
- קרן שאילתה יוצאת משולחן האנליסט ושולפת תשובה.

## סדר המשימות
r1 | r2, q1 | r3, q2, q3 | la1, flag1 | r4, qf1 (השאלות q2 ו-q3 הוקדמו אל r3, שבו הנושא שלהן נלמד)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Air Traffic Control | r1 | **The Tower's Jobs**: התאמה בין שש פונקציות SIEM לאירועים מהבוקר |
| 2 | When Does It Fire? | r2, q1 | **Does the Rule Fire?**: חוק threshold מול low and slow, וחוק sequence על שני ציר זמן |
| 3 | True, Benign or False | r3, q2, q3 | **Label the Outcome**: ‏TP, ‏BTP ו-FP (‏PsExec מאושר, ‏Luhn), כולל TP בחומרה נמוכה |
| 4 | The Spray Alert | la1, flag1 | תרגול **Anatomy of a Wazuh Alert** (‏rule 5712, ‏firedtimes ו-full_log) לפני ההתראה הנבחנת |
| 5 (בוס) | Ask Your Own Question | r4, qf1 | **Ask Sentinel**: שלוש שאילתות KQL על SigninLogs ו-DeviceProcessEvents, עד rclone |

**הפרדה מהשאלות הנבחנות:**
- דף החוקים מעריך ציר זמן, ולא נותן שם לסוג החוק של spray (q1).
- התור לא כולל את הגיבוי של SharePoint (q2) או התחברות VPN שפוספסה (q3).
- תרגול ה-Wazuh הוא חוק SSH, ולא התראת ה-spray או הממוצע שלה (la1, flag1).
- ה-KQL לא סופר כשלונות לפי חשבון מ-SecurityEvent (qf1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "1.2 Billion Events" | כניסה | תחנה 1 |
| Chapter 2: "Low and Slow" | אחרי Air Traffic Control | תחנה 2 |
| Chapter 3: "Severity Is a Guess" | אחרי True, Benign or False | תחנה 4 |
| Finale: "Ask It Yourself" | אחרי הבוס | החדר הבא: Log Sources Integration |
