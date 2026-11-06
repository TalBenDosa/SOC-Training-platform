# תסריט חדר 94: Threat Hunting Fundamentals

**שם המבצע:** Operation Long Shadow
**רמה:** מתקדם (כל פריימר מקופל, `fold: true`)
**העולם:** Alderney Semiconductors (בית תכנון שבבים בדוי): שמונה שרתי תכנון, תחנות הנדסה, ו-19 ימים עד שה-layout של שבב Kestrel יוצא למפעל.
**המנטור:** Theresa Mwangi, Threat Hunt Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
דוח של ענף השבבים מספר על קבוצה בשם Glass Heron, שישבה חודשים בתוך שתי חברות תכנון בלי התראה אחת. גם ב-Alderney אין התראות, ובשביל Theresa Mwangi שקט זה לא אותו דבר כמו נקי. הדירקטוריון מציג גרף שנראה מרגיע, והצוות צריך להחליט מה לבדוק, ולקבל את מה שהנתונים יגידו. הסיפור נגמר בצל ארוך יותר ממה שמישהו בבניין חשב.

## המכניקה הייחודית של החדר
- **A Hunt That Finds Nothing Is Still a Result:** השערה כתובה (H1) נבנית ל-`hunt` ב-SPL, בקונסולת Search. הספירה והערכים הנדירים מוצאים שלוש שורות חשודות, ולכל שלוש יש טיקט שינוי. ההשערה מופרכת, וזו התוצאה: המפה קטנה יותר. מעבדת המיון שאחריה מלמדת מתי מותר לכתוב "מופרך" ומתי היית בעצם עיוור.
- **Earn the Alert:** מעבדת `tune` שמחליטה מתי hunt הופך ל-detection. הריצה החוזרת על 30 יום נותנת מספרי precision ו-recall, והחמצה ידועה נשארת כתובה ברשומה.
- **Confirmed Means It Is Still Moving:** מעבדת `outbreak` שמראה למה ממצא מאומת הוא כבר לא hunt.

## העולם התלת-ממדי
אי קמפוס (`facility`, Campus) של Alderney Semiconductors עם Hub בשם THREAT HUNT HUB וארבעה מבנים לפי התחנות.

## סדר המשימות
r1, r2, q1, q2 | r3, q4 | q5, q3 | la1, flag1

(הסדר שונה. הסדר המקורי: r1, r2, r3, q1, q2, q3, la1, flag1, q4, q5. עכשיו r3 יושבת ליד q4, שצריכה אותה, q5 ליד מעבדות ה-beacon, q3 אחרי הממצא שהיא שואלת עליו, ו-la1 עם flag1 סוגרות את החדר כבוס. flag1 עדיין באה מיד אחרי la1, ולכן הניסוח "The log analysis event above" נשאר נכון. אין בחדר נוסח "Log Analysis N".)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Hypothesis | r1, r2, q1, q2 | **Read the Dwell Times Yourself** (worksheet), **Five Hunt Teams on the Maturity Ladder** (inspect), **Sort the Report by Attacker Pain** (sort), **Can This Hypothesis Fail?** (simulate), **Run One Hunt Through the Cycle** (sequence) |
| 2 | The Stack | r3, q4 | **Route Each Sign to the Log That Holds It** (reactor), **The Stack Ladder: Count, Then Read the Rare End** (hunt), **A Hunt That Finds Nothing Is Still a Result** (sort), **Which Parent Would the Technique Leave?** (match) |
| 3 | The Rhythm | q5, q3 | **Read the Gaps Between Requests** (worksheet), **Confirmed Means It Is Still Moving** (outbreak), **Earn the Alert: From Hunt to Detection** (tune) |
| 4 (בוס) | The Long Shadow | la1, flag1 | **Read a Signed Tool's Process Record** (anatomy), **Name, Hash or Behaviour?** (sort), **Follow the IDs Up the Tree** (trace) |

**הפרדה מהשאלות הנבחנות:**
- **q1 (למה הירידה ב-dwell time לא מבטלת ציד):** הרעיון נלמד ב-Read the Dwell Times Yourself על רשימת 11 מקרים של הענף, שם הלומד מחשב בעצמו 9, 7 ו-213. דוגמת הפריימר היא זמני אמבולנס בעיר. נתוני התעשייה של הנבחנת לא מופיעים, ואף שורה לא מזכירה את המסיחים על containment, ענן או ציות.
- **q2 (ציד התנהגות מול אינדיקטורים):** נלמד ב-Sort the Report by Attacker Pain על ntdsutil, פיצול קבצים וכלי ניהול מרוחק, ובדוגמת הפריימר על כנופיית גניבת רכב. אין שם LSASS, rundll32 או comsvcs, והמעבדה לא עוברת על ארבע האפשרויות.
- **q3 (מה קודם אחרי ממצא מאומת):** נלמד בפריימר של Confirmed Means It Is Still Moving על web shell בשרת ציבורי, ובלקח המשחק. הפריימר אומר רק מה כן קורה. אין בו שום מילה על איתחול המחשב או על שמירת הממצא בתוך צוות הציד, ו-Earn the Alert מגיעה אחרי שה-IR כבר קיבל את התיק, כך שהסדר נלמד בסיפור.
- **q4 (הליד החזק בערימה):** השיטה נלמדת ב-The Stack Ladder על התקנות שירות לפי נתיב קובץ, ובדוגמת הפריימר על autoruns. הקשר בין טכניקה להורה נלמד ב-Which Parent Would the Technique Leave? על w3wp.exe, sqlservr.exe, excel.exe, mshta.exe ו-java.exe. הצמד של הנבחנת לא מופיע, וגם אף צמד של מסיח לא מופיע במעבדות.
- **q5 (איזו תחנה משדרת beacon):** נלמד ב-Read the Gaps Between Requests על sleep של 900 שניות, תשובות של 1,204 בתים ושורה אחת של 18,540 בתים, ובדוגמת הפריימר על סוכן נכסים של 640 מחשבים. אין במעבדות WS-27, פרצי CDN או העלאות גדולות, והפריימר לא שולל את המסיחים אחד אחד.
- **la1, שאלה 1 (המספר בשורת הפקודה):** עובדת זיכרון. היא מודגמת באנטומיה על createdump.exe ו-PID 7316, ונבדקת שוב בשלב הראשון של Follow the IDs Up the Tree. המעבדות לא שואלות מה המספר 640, ואין בהן פורט, access mask או session ID. צורת ההרצה של rundll32 נלמדת בפריימר על desk.cpl התמים.
- **la1, שאלה 2 (למה זה עובר רשימות חסימה):** נלמד ב-Name, Hash or Behaviour? על certutil, bitsadmin, reg ו-mshta, ובדוגמת הפריימר על msiexec. אין שם mimikatz, procdump או comsvcs, ולא מוזכרים zero-day, הזרקה או שינוי שם.
- **flag1 (התהליך שהפעיל):** נלמד בשדה ParentBaseFileName באנטומיה, ובשני שלבי ההורה ב-Follow the IDs Up the Tree, שם התשובות הן powershell.exe ו-wmiprvse.exe. הערך של הנבחנת לא מופיע באף מעבדה, והוא נקרא מהרשומה הנבחנת.
- **שאלת הביניים של r1 (HMM4):** עובדת זיכרון. היא מופיעה בדרך אגב כשורה עם תווית ב-Five Hunt Teams on the Maturity Ladder, על צוות בדוי. המעבדה לא שואלת אותה.
- **שאלת הביניים של r2 (איזה שלב הופך ציד לשיפור קבוע):** נלמד בשלב האחרון של Run One Hunt Through the Cycle על ציד HTA, בניסוח אחר, וב-Earn the Alert. הממצא על LSASS לא מופיע.
- **האות המכריע של הבוס:** קריאת רשומה בכיוון מה הורץ, מה נאמר לו לעשות ומי הפעיל אותו. זה נלמד במעבדה משלו, Read a Signed Tool's Process Record, על רשומה של כלי אחר, תהליך יעד אחר ומחשב אחר.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "No Alerts" | כניסה | תחנה 1 |
| Chapter 2: "Nineteen Days" | אחרי The Hypothesis | תחנה 2 |
| Chapter 3: "Layout Week" | אחרי The Stack | תחנה 3 |
| Finale: "The Long Shadow" | אחרי The Long Shadow | החדר הבא |
