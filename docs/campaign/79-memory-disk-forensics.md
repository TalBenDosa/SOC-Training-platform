# תסריט חדר 79: Memory & Disk Forensics for Analysts

**שם המבצע:** Operation Pagefile
**רמה:** מתקדם
**העולם:** Harrowgate Museum Trust (נאמנות מוזיאונים בדויה): חמישה מוזיאונים, מסד נתונים אחד לאוספים, ותשעה ימים עד שאוצר Kestrel Hoard מוצג לקהל.
**המנטור:** Yusra Lindahl, DFIR Analyst. (בטקסטים אין לשון זכר או נקבה.)

## סיפור הרקע
על תחנת העבודה של הרשמת יושב קובץ שטוען שנוצר ב-2017, בין תוכנות הקטלוג הישנות, אבל אף אחד לא פתח את התיקייה הזאת שנים. במוזיאון יודעים שתווית על ויטרינה יכולה להגיד כל דבר, ולכן בודקים אותה מול פנקס הרישום. כך גם כאן: למישהו יש עניין בלוח הזמנים של השליחים שמביאים את האוצר, ומי שהשאיר את הקובץ זייף לו תעודת יוחסין. המשימה של Yusra: לקחת image ממכונה שעדיין רצה, לקרוא את הזיכרון מול הדיסק, למצוא מה שהמוחקים פספסו, ולהחליט מתי מושכים את התקע.

## המכניקה הייחודית של החדר
- **Two Timelines:** חדר 43 נותן שמות לארטיפקטים, והחדר הזה מעמיד אותם זה מול זה. שני `trace` קוראים פלט Volatility 3 אמיתי (`windows.pslist`, `windows.mftscan.MFTScan`, `windows.netscan`) לצד `$MFT`, `$UsnJrnl`, Prefetch, ShimCache ו-Amcache, עד שקובץ מסגיר את עצמו כי `$STANDARD_INFORMATION` ו-`$FILE_NAME` לא מסכימים. בסוף הלומד מוחק שורה אחת מטיוטת ה-timeline.
- **Tune a Sweep Across Every $MFT:** `tune` על הפער בין השעונים ועל האפסים בשבר השנייה. המטרה ניתנת להשגה רק בסף צר, ודגימה אחת נשארת מחוץ לכלל בכוונה, כי הזמנים שלה הועתקו מ-DLL של Windows.
- **Same Tool, Different Night:** `queue` שמלמד את האות המכריע של הבוס על כלים אחרים: אותו כלי מפחיד, ארבעה שדות, ורשומת שינוי שחייבת להתאים למארח, לחשבון ולשעה.

## העולם התלת-ממדי
אולם קלפים (`facility`, hall) עם `core: "matrix"`: קלף אחד לכל תחנה. theme ‏`pagefile`, scene ‏`facilitypagefile`.

## סדר המשימות
r1, r2, q1, r3, q2 | r4, la1, f1 | r5, m1, q3 | r6, o1 | ac1

**הסדר שונה מהחדר המקורי.** במקור f1 בסוף החדר, רחוק מהלוג שהוא מתייחס אליו, ו-ac1 באמצע, למרות שזו ההחלטה הקשה בחדר והיא הופכת את מה ש-r5 מלמד.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Image | r1, r2, q1, r3, q2 | **Hands on a Live Machine** (defuse), **Name the Volatility Plugin** (codebreak), **Which Image Holds It?** (sort), **Find the Holes in a Custody Record** (hotspot) |
| 2 | Two Timelines | r4, la1, f1 | **Two Timelines: Read Memory Beside Disk** (trace), **Three More Witnesses: Prefetch, ShimCache, Amcache** (trace), **Tune a Sweep Across Every $MFT** (tune), **Time a Gap From the Journal** (worksheet) |
| 3 | What Stays Behind | r5, m1, q3 | **Follow an Eraser Across Sources** (trace), **What Did the Eraser Miss?** (codebreak) |
| 4 | Pull the Plug | r6, o1 | **Contain or Preserve? Four Live Calls** (defuse) |
| 5 (בוס) | The Last Shadow | ac1 | **Same Tool, Different Night** (queue), ואז ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1** (מה קודם): הפריימר של Hands on a Live Machine מלמד ש-sockets ותהליכים נקראים מתוך image של זיכרון, והחוטים מלמדים snapshot כפתרון זמני ואיסור התקנה. המעבדה בוחנת את המקרה החריג, dump שלא יכול להתחיל, ולא שואלת מה קודם. שונה: חוסר מקום בכונן איסוף, לא התחלת עבודה רגילה.
- **q1** (התצורה מוצפנת בדיסק, גלויה רק ב-RAM): הפריימר של Name the Volatility Plugin ופריט `unpacked` ב-Which Image Holds It?. שונה: רשימת סיומות של loader ארוז, לא דומיין C2 ומפתח.
- **שאלת הביניים של r3** (מתי מחשבים SHA256): הפריימר של Find the Holes in a Custody Record והשורה `hash`. שונה: רשומה של קבלן על HMT-COLL-01, לא winpmem שסיים עכשיו.
- **q2** (image ממערכת חיה, מה ה-hash מוכיח): הפריימר והשורות `blocker` ו-`claim` ב-Find the Holes in a Custody Record. שונה: רשומה של dump זיכרון בלבד, בלי image של דיסק, והלומד מוצא טענות שגויות ולא עונה לעמית.
- **la1 שאלה 1** (פער `$SI` מול `$FN`): הפריימר של Two Timelines ושלבים `mft` ו-`ram`. הלומד פוסל את שאר ההסברים בעצמו, והפריימר של Tune a Sweep Across Every $MFT מלמד רק כלי הגירה ושעונים גסים. שונה: clsync32.exe ב-ProgramData, לא הקובץ ב-Downloads.
- **la1 שאלה 2** (`$UsnJrnl` כעד עצמאי): הפריימר של Two Timelines ושלב `usn`, שבו הלומד מוצא את השורה הראשונה עם סיבת השינוי ונושא את הזמן הלאה. שונה: הלוג בפורמט MFTECmd, וההסבר לא עובר על המסיחים.
- **f1** (שניות בין יצירה אמיתית לשינוי זמנים): Time a Gap From the Journal. שונה: 75 ו-95 שניות, ושורת SecurityChange כמסיח, לא 107.
- **שאלת הביניים של r5** (`wevtutil cl` על כל הערוצים): הפריימר שואל איפה כל מקור נשמר ומה הוא מתעד, ושורות ה-EDR ב-Follow an Eraser Across Sources מראות טלמטריה שנשמרה מחוץ למארח. שונה: ניקוי של System, Application ו-PowerShell, ולא של כל הערוצים.
- **m1** (התאמת טכניקה לשארית): העובדות מופיעות כנתון, ולא נשאלות כזוגות. 1102 בפריימר של Follow an Eraser Across Sources, `$FN` ו-`$UsnJrnl` ב-Two Timelines, טלמטריית תהליכים בשלב `edr`, ו-EPROCESS בפריימר של Name the Volatility Plugin. What Did the Eraser Miss? מתרגל את אותו דפוס על מוחקים אחרים: del של Prefetch, SDelete ו-fsutil.
- **q3** (1102 וה-pivot): Follow an Eraser Across Sources. שונה: החקירה מתחילה מהתראת firewall ולא מעמית שמרים ידיים, עם אירועי 104 ולא Security עם 1102, וה-pivot קורה בפועל ולא נבחר מרשימה.
- **o1** (סדר התגובה): Contain or Preserve? Four Live Calls. כל חוט הוא החלטה אחת: בדיקה שההתראה עדכנית (`stale`), בידוד ששומר על RAM ו-dump שכדאי כשיש זמן (`burn`), והסלמה (`legal`). הפריימר והדוגמה לא נותנים רצף, והמעבדה לא מבקשת לסדר דבר.
- **ac1** (הבוס): האות המכריע נלמד במעבדה משלו, Same Tool, Different Night, כולל המושג benign true positive. שונה: sdelete, fsutil, cipher ו-vssadmin list בלבד, בלי גיבוי שמוחק shadow copies.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Label on the Case" | כניסה | תחנה 1 |
| Chapter 2: "Nine Days" | אחרי The Image | תחנה 2 |
| Chapter 3: "Friday Morning" | אחרי What Stays Behind | תחנה 4 |
| Finale: "Doors Open" | אחרי The Last Shadow | החדר הבא |
