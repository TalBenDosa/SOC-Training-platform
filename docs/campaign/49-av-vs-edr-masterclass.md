# תסריט חדר 49: AV vs EDR Masterclass

**שם המבצע:** Operation Second Opinion
**רמה:** בינוני
**העולם:** Wrenfield Veterinary Group (רשת בדויה של מרפאות וטרינריות): ‏64 מרפאות, 700 עובדים, מכשירי רנטגן, תיקי חיות, וקונסולת אנטי-וירוס שירוקה כבר שש שנים.
**המנטורית:** Beatriz Monteiro, ראש אבטחת IT.

## סיפור הרקע
באביב שעבר מרפאה ב-Ludlow הוצפנה במהלך סוף שבוע, והקונסולה נשארה ירוקה כל הזמן. ל-Beatriz יש תקציב ל-EDR ודירקטוריון שרוצה לדעת למה הכלי הישן לא הספיק. התשובה שלה צריכה להיות מדויקת.

## המכניקה הייחודית של החדר
**ארבע דלתות:** ארבע שכבות האנטי-וירוס (חתימות, היוריסטיקה, סנדבוקס, למידת מכונה) הן ארבע דלתות. קוראים את הרעיון ואת מה שקרה על מחשב של המרפאה, ועונים על הבדיקה כדי לפתוח. הדלת האחרונה מגלה את המגבלה המשותפת לכולן.

## העולם התלת-ממדי: Second Opinion
- קשת סורק (AV · ALL GREEN) שקבצים עוברים דרכה.
- רוח רפאים (NO FILE) שעוברת דרך הקשת בלי שמישהו יראה.
- מחשב נייד בתוך טבעות USER, ‏ETW ו-KERNEL.
- שלוש קונסולות: FALCON, ‏SINGULARITY, ‏DEFENDER XDR.
- עץ תהליכים עם צומת חשוד אחד ומגן הכרעה.

## סדר המשימות
r1, r2, r3 | r4, q1, q2 | r5, r6 | r7, r8, r9, q3 | r10, la1, f1 (במקור כל עשר הקריאות היו לפני השאלות)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Old Guard | r1, r2, r3 | **Beat the Signature**: טרמינל ClamAV, ‏sha256sum ו-cmp; **Four Doors of the Old Guard** (ארבע דלתות) |
| 2 | Green Console | r4, q1, q2 | **What the Scanner Saw**: מיון אירועי סוף השבוע |
| 3 | Under the Hood | r5, r6 | **Wire the Sensor**: התאמת חיישן למה שהוא מדווח |
| 4 | Three Consoles | r7, r8, r9, q3 | **Hunt in Defender**: ציד ב-Advanced Hunting |
| 5 (בוס) | The Second Opinion | r10, la1, f1 | הלוג הנבחן |

**הפרדה מהשאלות הנבחנות:**
- הדלתות והמיון בלי AMSI, ‏PowerShell מקודד או LOLBins בשמם (q1, ‏q2), ובלי אנטרופיה (checkpoint של r3).
- התאמת החיישנים בלי AMSI ‏(q1) ובלי access masks ‏(q3, ‏checkpoint של r7).
- הציד לא נוגע ב-LSASS, הזרקה, דגלי PowerShell, בידוד או tamper protection ‏(la1, ‏f1, ‏checkpoint של r9).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Six Years of Green" | כניסה | תחנה 1 |
| Chapter 2: "One Byte" | אחרי The Old Guard | תחנה 2 |
| Chapter 3: "Nothing to Scan" | אחרי Green Console | תחנה 3 |
| Finale: "The Board Meeting" | אחרי הבוס | החדר הבא |
