# תסריט חדר 63: Reporting & Documentation

**שם המבצע:** Operation Paper Trail
**רמה:** בינוני
**העולם:** Brackenridge Mutual Housing (עמותת דיור בדויה): 5,200 דירות, 210 עובדים, ופורטל דיירים שמחזיק את קודי ה-key-safe שמטפלים משתמשים בהם כדי להגיע לדיירים קשישים.
**המנטור:** Aroha Tremblay, SOC Team Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
בלילה של יום שני עלה לפורטל הדיירים web shell. האנליסט של משמרת הערב, Kit Marsh, בלם את השרת, כתב פתק דק ("Contained", "No other systems affected") והלך הביתה. בשלוש לפנות בוקר הלומד מקבל את הטיקט מ-Aroha, יחד עם עט אדום. במהלך החדר התקרית ממשיכה: דוח למנכ"ל, מסירת משמרת, מכתב מעורכי דין של ועד הדיירים שמפעיל legal hold, ואז הדיסק שנשמר חושף מתי התוקף באמת נכנס. בסוף הטיקט מגיע לסגירה. המסר: פתק נכתב בשביל מי שפותח אותו בשלוש לפנות בוקר, ובשביל מבקר בעוד שנה.

## המכניקה הייחודית של החדר
**העט האדום (The Red Pen).** הלומד עורך כתיבה אמיתית של אנליסטים, ולא רק קורא עליה.
- **The Red Pen: Weak Note, Strong Note:** `spotdiff` של טיקט חלש לצד טיקט חזק. השורות שמסמנים הן טענה מעורפלת, ראיה חסרה או מסקנה בלי הוכחה. שורה כמו "No other systems affected" נראית תמימה, והיא המסוכנת ביותר. שינויי ניסוח תמימים עולים בחיים.
- **Pull the Facts from the Raw Ticket:** `worksheet` ששולף מ-worklog גולמי את העובדות שפתק טוב חייב להחזיק (מי, מה, מתי, איפה, למה), כולל עובדה אחת שפשוט לא קיימת, והתשובה הנכונה לה היא "לא".
- **The Red Pen: The Evidence Register:** אותו עט על רישום ראיות: מה לא יעמוד מול שאלה של עורך דין.

## העולם התלת-ממדי
אולם קלפים (`facility`, פריסת hall) של Brackenridge, עם ליבת `matrix`: חמישה קלפים לפי התחנות. ה-`theme` הוא `papertrail` וה-`scene` הוא `facilitypapertrail`.

## סדר המשימות
rep-read-1, rep-q1 | rep-read-2, rep-q3 | rep-read-3 | rep-read-4, rep-q2, rep-log-1 | rep-ac1

הסדר השתנה מהסדר השמור (r1, r2, r3, r4, q1, q2, q3, log-1, ac1), כי שם ארבע הקריאות יושבות ברצף בתחילת החדר ואין קיבוץ לתחנות. הקריאות נשארו בסדר המקורי, כי q2 ו-log-1 מפנות אל "Reading 3" ו-"Reading 4" לפי מספר. log-1 צריכה את שתיהן, ולכן היא באה אחרי קריאה 4.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Case Notes | rep-read-1, rep-q1 | **Who Reads This Note?** (match), **Ticket, Handover or Executive Summary?** (sort), **Pull the Facts from the Raw Ticket** (worksheet), **The Red Pen: Weak Note, Strong Note** (spotdiff) |
| 2 | The Handover | rep-read-2, rep-q3 | **Read the SOC Dashboard** (rush), **Work the Weekly KPI Board** (worksheet), **Build the Shift Handover** (sort), **One Page for the Chief Executive** (intercept) |
| 3 | The Hold | rep-read-3 | **Legal Hold: What Stops Now?** (intercept), **The Red Pen: The Evidence Register** (spotdiff), **Ask It in the Review?** (sort), **Which Case System Is This?** (match) |
| 4 | The Three Clocks | rep-read-4, rep-q2, rep-log-1 | **Name the Clock** (sort), **Four Clocks on One Incident** (worksheet), **What Was Actually Measured?** (inspect), **Read a Closed Ticket Field by Field** (anatomy, חימום ל-log-1) |
| 5 (בוס) | The Sign-Off | rep-ac1 | **The Closure Gate** (intercept, חימום), ואז ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות (איפה נלמד כל רעיון, ומה שונה):**
- ‏rep-read-1, שאלת ביניים (אין רישום = אין תיעוד): **Who Reads This Note?** מלמדת את ארבע הסיבות ואת "If it's not documented, it didn't happen". הדוגמה היא טיקט פתוח של web shell, לא בידוד בלי שום רישום.
- ‏rep-q1 (מה חסר ב-"Ransomware. Cleaned up."): **The Red Pen** ו-**Pull the Facts** מלמדות שפתק צריך קו זמן, מערכות, IOC, פעולות ו-root cause. **Ticket, Handover or Executive Summary?** מפרקת את המסיחים: הטיקט לא מוחלף בהנדאובר, ותקציר המנהלים הוא מסמך נפרד. ב-Pull the Facts מוסבר ש-Category הוא סוג אירוע, לא משפחת נוזקה. התקרית היא web shell, לא ransomware, ואין שם ניסוח של השאלה.
- ‏rep-read-2, שאלת ביניים (MTTD): הקלפים r1 ו-r2 ב-**Read the SOC Dashboard** מלמדים היכן השעון מתחיל ונעצר, בלי דוגמה מספרית של השאלה.
- ‏rep-q3 (שיעור FP): **Read the SOC Dashboard** ו-**Work the Weekly KPI Board** מלמדות את הנוסחה ואת קו ה-90%, על 85% ו-95% מתוך 3,400 ו-6,000 התראות. לעולם לא 92% ולא 10,000.
- ‏rep-q2 (dwell time): **Name the Clock** ו-**Four Clocks on One Incident** מלמדות שהשעון מתחיל ב-foothold ונעצר בזיהוי ולא בבלימה. המספרים הם 47 ו-217 דקות על web shell, לא 1:30 על VPN גנוב.
- ‏rep-read-4, שאלת ביניים (MTTA): **Four Clocks on One Incident** מחשבת MTTA של 8 דקות, לא 6.
- ‏rep-log-1, שאלה 1 (פער ב-chain of custody): **The Red Pen: The Evidence Register** מלמדת מי, מתי, איך נשמר והאש, וקוראת רשומה לפי מה שחסר בה. הראיות הן דיסק ולוגי IIS, לא memory dump. **Legal Hold: What Stops Now?** מפרקת את המסיחים: IOC נשארים בטיקט, ו-blameless לא אומר למחוק עובדות. **Ask It in the Review?** מראה שביקורת היא תהליך נפרד.
- ‏rep-log-1, שאלה 2 (Respond מול Resolve): **Four Clocks on One Incident** ו-**Read a Closed Ticket Field by Field** מלמדות לבדוק את השדה מול הזמנים. כאן 5,340 דקות ו-34 דקות, לא 145 ו-17.
- ‏rep-ac1 (הבוס): **The Closure Gate** היא מעבדה ייעודית לאות המכריע: הפרת SLA דורשת רישום וחתימה של ראש משמרת גם כשהכול נבלם. עשרה טיקטים אחרים ומספרי SLA אחרים, כולל מקרה שבו הדגל שגוי ומקרה שכבר נחתם. לעולם לא פישינג של גניבת סיסמה, ולא 145 מול 120.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "One Thin Note" | כניסה | תחנה 1 |
| Chapter 2: "The Morning After" | אחרי The Handover | תחנה 3 |
| Chapter 3: "What the Disk Kept" | אחרי The Hold | תחנה 4 |
| Finale: "A Year Later" | אחרי הבוס | החדר הבא |
