# תסריט חדר 32: Windows Privilege Escalation & UAC Bypass

**שם המבצע:** Operation Quiet Climb
**רמה:** מתקדם
**העולם:** Ardent Rail (מפעילת רכבות בדויה): 140 תחנות, רשת איתות שאסור לה לעצור ו-6,000 תחנות קצה של Windows, ממכונות כרטיסים ועד שולחנות dispatch.
**המנטור:** Priya Natarajan, Threat Hunter.

## סיפור הרקע
דריסת רגל מפישינג על שולחן dispatch היא מטרד. אותה דריסת רגל ב-High integrity, או כ-SYSTEM, מגיעה לכל אישור גישה (credential) על המחשב. Priya צדה את הטיפוס השקט שבאמצע: הצעד מ-Medium ל-High, ומחשבון שירות ל-SYSTEM. הלילה היא רוצה שתעבור איתה על ארבעה מחשבים של Ardent ותבין בכל אחד איך מישהו טיפס, או למה לא.

## העולם התלת-ממדי: Integrity Ladder
- ארבעה משטחי זכוכית (LOW, ‏MEDIUM, ‏HIGH, ‏SYSTEM) וכדור תהליך שמטפס ביניהם.
- כספת lsass.exe עם קרן גישוש.
- מפתח handler שנכתב מחדש עם קשת עקיפה ל-High.
- מסכת SeImpersonate ונתיב שירות עם רווחים.
- טבעת הכרעה שנסגרת סביב הכול.

## סדר המשימות
r1 | r2, q1 | r3, la1, f1 | r4, q2, r5, q3 | ac1, m1, o1, qf1 (במקור f1 היה אחרי o1. הוא עבר אל התחנה של la1, כי הוא שואל על אותו אירוע)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Integrity Levels | r1 | **Read the Column**: ‏Process Explorer עם עמודת Integrity (‏renderer ב-Low, אפליקציה של אדמין ב-Medium, ‏Event Viewer ב-High) |
| 2 | Reaching LSASS | r2, q1 | **Who Opened LSASS?**: מיון חמש גישות Sysmon 10 לפי מי ביקש, ולא רק לפי ה-mask |
| 3 | UAC Bypass | r3, la1, f1 | **The Rewritten Handler**: ‏reg query ל-mscfile ב-HKCU מול HKLM, הסקריפט שנשתל והרמה שבה רץ |
| 4 | Road to SYSTEM | r4, q2, r5, q3 | **What Can the App Pool Do?** (‏whoami /priv ו-spooler) ו-**The Path With Spaces** (‏wmic, ‏icacls, ‏Signal.exe שנשתל) |
| 5 (בוס) | Read the Jump | ac1, m1, o1, qf1 | **Three Jumps**: שלוש קפיצות Medium ל-High. ‏sdclt בלי prompt ובלי רשומה מול Event Viewer שעולה בעצמו |

**הפרדה מהשאלות הנבחנות:**
- מיון ה-LSASS הוא של גישות Sysmon 10 שניתנו, ולא בקשת 4656 שנכשלה (q1).
- קונסולת ה-hijack היא וריאנט eventvwr/mscfile שנקרא עם reg query. אין בה fodhelper, ‏ms-settings או מספר אירוע (la1, ‏f1, ‏o1).
- ה-app pool הוא אתר אחר מזה של q2.
- הנתיב הלא-מצוטט הוא Rail Apps, ולא Meridian Sync ‏(q3).
- גיליון הקפיצות לא כולל את ה-installer של ac1.
- אין כתיבת KQL ‏(qf1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Quiet Climb" | כניסה | תחנה 1 |
| Chapter 2: "Who Asked for LSASS" | אחרי Reaching LSASS | תחנה 3 |
| Chapter 3: "No Prompt" | אחרי UAC Bypass | תחנה 4 |
| Finale: "Approved or Stolen" | אחרי הבוס | החדר הבא: MITRE ATT&CK |
