# תסריט חדר 9: Timestamps, Timezones & Building a Timeline

**שם המבצע:** Operation Zero Hour
**רמה:** מתחילים
**העולם:** Varden Shipping (חברה בדויה) עם משרדים בתל אביב, ניו יורק ובנגלור.
**המנטורית:** Ines Moreau, Incident Response Lead. Raj Iyer (IT בנגלור) מופיע בבוס.

## סיפור הרקע
ארבעים מערכות, וכל אחת אומרת מה השעה. רובן לא מסכימות. Ines צריכה ציר זמן שההנהלה יכולה לסמוך עליו, מדויק עד השנייה. לומדים לקרוא כל שעון, לסדר כל אירוע בסדר האמיתי שלו, ולמצוא את שעת האפס.

**כל ההמרות במעבדות חושבו בפועל.** ישראל ב-UTC+2 בנובמבר, ניו יורק ב-EST ‏(UTC-5) אחרי סוף שעון הקיץ, והודו ב-UTC+5:30.

## העולם התלת-ממדי: Chrono
שלושה שעונים עולמיים: UTC, תל אביב (‎+2) וניו יורק (‎-5). שרת NTP משגר קרני סנכרון לשלושה מגדלי מקור (חומת אש, DC, EDR). מלפנים מסילת ציר זמן שעליה חרוזי אירועים, שמתחילים בסדר מבולבל ונכנסים לסדר האמיתי. בבוס, סוגר DWELL TIME אדום נפרש משעת האפס ועד הזיהוי.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Read the Clock | r1 | **Name That Timestamp** (‏ISO 8601, epoch בשניות, epoch במילישניות, FILETIME, syslog). **Convert Everything** (bash): ‏date -u -d @, חלוקה ב-1000 למילישניות, ו-FILETIME עם python |
| 2 | One Instant, Three Zones | r2, q1, f1 | **One Instant, Three Offices**: ‏TZ= date לכל אחד מהמשרדים. **Which Clock Is It?**: המרה של שלוש הצהרות ל-UTC והשוואה |
| 3 | Fix the Order | r3, r4, q2 | **Who's Out of Sync?**: ‏timedatectl -H על שלושה מארחים. **Correct the Skew**: תיקון של 3 דקות מהר ו-2 דקות לאט, ובניית הסדר האמיתי. **Queue Order Isn't Event Order** (השתלטות על חשבון) |
| 4 | Same Instant, Two Times | la1 | תרגול **Anatomy of a Timestamped Event** על רשומת Okta, ואז ההתראה הנבחנת |
| 5 (בוס) | Zero Hour | r5, m1, o1, ac1 | **One Logon or Two?**: מעקב מלוג ה-VPN ל-4624 ב-DC, כלומר אותה פעולה שנראתה פעמיים. **The Year Nobody Wrote**: הסקת השנה בקובץ syslog. אחר כך ההכרעה על הלוגון של 03:50 |

**הפרדה מהשאלות הנבחנות:**
- אין ערך בן 13 ספרות מ-q1 או מ-f1.
- מעבדת סדר התור היא שרשרת השתלטות על חשבון (q2 שואלת על DLP, דוא"ל ו-EDR).
- התרגול הוא Okta ולא Falcon (la1).
- אף מעבדה לא ממירה את הלוגון של בנגלור (ac1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Forty Clocks" | כניסה | תחנה 1 |
| Chapter 2: "Three Clocks Disagree" | אחרי Fix the Order | תחנה 4 |
| Chapter 3: "Same Instant" | אחרי Same Instant, Two Times | תחנה 5 |
| Finale: "Zero Hour" | אחרי הבוס | החדר הבא: Log Entry Anatomy |
