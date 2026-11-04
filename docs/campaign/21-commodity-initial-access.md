# תסריט חדר 21: Commodity Initial Access

**שם המבצע:** Operation Bait Shop
**רמה:** מתחילים
**העולם:** Brennan & Lowe Architects (משרד אדריכלים בדוי): 300 עובדים, קבצי CAD גדולים, והרגל לחפש כלים חינמיים ברשת.
**המנטורית:** Yara Nasser, אנליסטית מודיעין איומים.

## סיפור הרקע
ב-2022 Office הפסיק להריץ מאקרו מקבצים שהגיעו מהאינטרנט. התוקפים לא הפסיקו; הם החליפו את הפיתיון. Yara עוקבת אחרי איך הפיתיון נראה היום:
- CAPTCHA שמקליד פקודה בעצמו.
- לוח העתקה (clipboard) שמשקר.
- תוצאה ממומנת בחיפוש.
- קובץ דיסק (ISO).
- לשונית דפדפן שכורה מטבע.

עוברים בחנות הפיתיונות ולומדים לזהות כל פיתיון לפני שמישהו נופל בו.

## העולם התלת-ממדי: Bait Shop
שישה פיתיונות תלויים על ווים בקשת סביב תחנת עבודה אחת:
- מסמך מאקרו נעול במנעול.
- לוח CAPTCHA מזויף שחושף את ההוראות האמיתיות: Win+R ‏Ctrl+V ‏Enter.
- שתי מחרוזות ארנק שנראות זהות, אבל האמצע שלהן שונה.
- ערימת תוצאות חיפוש שבה שתי העליונות זוהרות באדום.
- דיסק מסתובב עם תג ZoneId=3.
- לשונית דפדפן שגלגל השיניים שלה שולח shares אל relay.

כשתחנה פתוחה, קו מקווקו מחבר את הפיתיון שלה אל תחנת העבודה.

## סדר המשימות (שונה כדי שכל תחנה תהיה רציפה)
r1 | r2, q1, ac1 | r3, q2 | r4, la1 | r5, q3 | r6, la2, f1, q4, m1, o1

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | After Macros | r1 | **Why the Macro Didn't Run**: הודעת Word, ‏Zone.Identifier ו-GPO |
| 2 | The Fake CAPTCHA | r2, q1, ac1 | **Take the Lure Apart**: ‏hotspot על דף ה-ClickFix. **What Did They Paste?**: ‏reg query RunMRU |
| 3 | The Lying Clipboard | r3, q2 | **Copied vs Pasted**: כתובות עם התחלה וסוף זהים ואמצע שהוחלף |
| 4 | The Sponsored Result | r4, la1 | **Which Result Is Real?**: ‏hotspot על תוצאות חיפוש ל-WinSCP |
| 5 | The Disc Image | r5, q3 | **Check the Mark**: ‏Get-Item -Stream ו-Get-Content Zone.Identifier על מחשב מעודכן |
| 6 (בוס) | The Mining Tab | r6, la2, f1, q4, m1, o1 | **Anatomy of a Stratum Message**: ‏subscribe, ‏authorize, ‏job ו-submit |

**הפרדה מהשאלות הנבחנות:**
- מעבדות ה-ClickFix לא עוסקות בהיעדר file_create (q1) או ב-Chocolatey (ac1).
- דף ה-clipper משווה כתובות, ולא בוחר צעד חקירה (q2).
- דף החיפוש עוסק ב-WinSCP, ולא ב-7zSetup (la1).
- קונסולת ה-MOTW רצה על מחשב מעודכן, ולא על המחשב הלא מעודכן של q3.
- תרגול ה-Stratum לא כולל את ה-WebSocket או את ה-IP של la2 ו-f1, ולא את הסימפטומים של q4.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "They Changed the Bait" | כניסה | תחנה 1 |
| Chapter 2: "Win+R, Ctrl+V, Enter" | אחרי The Fake CAPTCHA | תחנה 3 |
| Chapter 3: "Sponsored, Mounted, Trusted" | אחרי The Sponsored Result | תחנה 5 |
| Finale: "The Tab That Mines" | אחרי הבוס | החדר הבא: macOS Security Fundamentals |
