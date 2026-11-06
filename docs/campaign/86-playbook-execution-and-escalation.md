# תסריט חדר 86: Running the Playbook, and Knowing When to Stop

**שם המבצע:** Operation Runbook
**רמה:** בינוני
**העולם:** Greenhithe Foods Distribution (מפיצת מזון בדויה): שלושה מרכזי הפצה, 430 עובדים, ומזון מקורר בדרך ל-1,100 חנויות לפני שהן נפתחות. ההעמסה מתחילה ב-02:00.
**המנטור:** Sanaa Kowalczyk, IR Coordinator. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
על שולחן ה-SOC של Greenhithe יושב קלסר אדום, ובו דף לכמעט כל דבר שיכול להשתבש לפני ההעמסה. רוב הדפים הם העבודה של Sanaa, ודווקא משם מגיעה האזהרה הקבועה: דף יכול לטעות. הלילה נכנסת התראה אחת על מחשב dispatch אחד, GFD-DISP-07, והדף PB-22 ברור מאוד: מחשב אחד, בידוד, בנייה מחדש, סגירת הטיקט. הלומד מריץ את הדף כמו שצריך, מגלה איפה המציאות מפסיקה להתאים לנייר, ומחליט מה עושים עם צעד 4 שפתוח מולו.

## המכניקה הייחודית של החדר
- **When the Page Doesn't Match:** מעבדת `simulate`. ארבעה טיקטים של השבוע רצים על אותו דף צעד אחר צעד, וכל אחד נשבר במקום אחר: דף שמתאים עד הסוף, כלי שיצא משימוש, מחשב שיש לו תפקיד שני, ושער היקף שנופל הלילה.
- **Spot the Line, Give the Reason:** מעבדת `trace` שמיד אחריה. הפעם הלומד עצמו לוחץ על השורה שבה הדף הפסיק להתאים, ואז בוחר את הערת הטיקט שעומדת בביקורת.
- **Which Branch Applies?:** ה-`defuse` לפני הבוס: ממשיכים, יורדים משורה אחת, או עוצרים. לא כל סטייה היא הסלמה, ורוב השערים נפתחים.
- **הלקח של החדר:** דף הוא רצפה ולא תקרה, וצעד שדולגו עליו צריך סיבה רשומה. חדר 66 מכסה playbooks אוטומטיים, וכאן זה האדם שמריץ את הדף.

## העולם התלת-ממדי
אי קמפוס (`facility`, Campus) של Greenhithe Foods עם Hub בשם INCIDENT RESPONSE HUB וארבעה מבנים לפי התחנות.

## סדר המשימות
r1, o1 | r2, la1, q1, m1 | la2 | ac1, q2, r3, f1

(הסדר המקורי נשמר. התחנה האחרונה מכילה את ac1 ואת שלוש המשימות שיכולות לבוא רק אחריה.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Binder | r1, o1 | **What a Page Says Before Step 1** (inspect), **Read-Only or Changes Something?** (rush) |
| 2 | Walk the Page | r2, la1, q1, m1 | **When the Page Doesn't Match** (simulate), **Spot the Line, Give the Reason** (trace), **Four Words for the Ticket** (codebreak), **Read a Sign-In Record Field by Field** (anatomy), **What the Fix Leaves Behind** (match), **Done, or Only Ticked?** (sort) |
| 3 | The Other Way Round | la2 | **Ask It the Other Way Round** (worksheet), **Count It, or Rule It Out?** (intercept), **What Came Before the Success?** (sort) |
| 4 (בוס) | The Call | ac1, q2, r3, f1 | **Which Branch Applies?** (defuse), **Sign It Off, or Send It Back?** (queue), **Build the Page to Sanaa** (sequence), **What the Binder Gets From Your Ticket** (match) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (מה דף לא יכול לדעת):** עובדת זיכרון, ולכן היא מופיעה רק כשורה עם תווית ב-What a Page Says Before Step 1, בשורה Covers, והמעבדה לא שואלת אותה. אף ניסוח של אפשרות לא מופיע.
- **o1 (סדר הריצה של IR-014):** הרעיון, קריאה לפני שינוי ומדידה לפני תגובה, נלמד ב-Read-Only or Changes Something? על פעולות בתחנת עבודה (בידוד, הריגת תהליך, חסימת דומיין). אף פריט של o1 לא מופיע. הדף המלא של PB-22 נחשף רק בתחנה 2, אחרי ש-o1 כבר נפתרה.
- **la1, שאלה 1 (אימות):** נלמד ב-Read a Sign-In Record Field by Field: הערך 0 מוצג כעובדה בשדה ResultType, אבל הרשומה עצמה היא 53000: Conditional Access דרש מכשיר תואם, והמכשיר לא תואם. הסיכון מוצג כדעה, ו-CorrelationId כקיבוץ של זרימת בקשה אחת.
- **la1, שאלה 2 (notApplied):** שלושת הערכים של ConditionalAccessStatus מוצגים בשדה, אבל הערך ברשומה הוא failure עם multiFactorAuthentication. במעבדה אין notApplied כערך של רשומה, ואין singleFactorAuthentication כערך של רשומה.
- **la1, שאלה 3 (הצעד הבא):** נלמד בפריימר של When the Page Doesn't Match, בנקודה על pivot, ובריצות של GFD-INC-3318. שם ה-pivot הוא על hash של קובץ, לא על מאפייני התחברות.
- **q1 (למה איסוף לפני בלימה):** נלמד ב-What the Fix Leaves Behind: מנהל depot רוצה בנייה מחדש, לא עמית שמעיר על טיקט. מה שנשאר מאחור הוא משימה מתוזמנת, Run key, דומיין שני וכלי גישה מרחוק. אין במעבדה איפוס סיסמה, כלל דואר או consent של אפליקציה.
- **m1 (מה כל צעד מייצר):** נלמד ב-Done, or Only Ticked? על שורות טיקט של PB-22. השאלה שם היא אם צעד הושלם או רק סומן, ואין התאמה של צעד לתוצר בניסוח של m1.
- **la2, שאלה 1 (אילו שדות זהים):** הרעיון, ערך אחד חלש וכמה ערכים מדויקים יחד חזקים, נלמד ב-Count It, or Rule It Out? על מכשירים, hash, URL ו-user agent. אין במעבדה השוואה בין שתי התחברויות.
- **la2, שאלה 2 (ניקוד סיכון לכל אירוע):** נלמד ב-Ask It the Other Way Round: התראה אחת מול חמישה מכשירים, כי כל זיהוי שפט את המכשיר שלו. שדה הסיכון של Entra נלמד באנטומיה, כדעה בזמן אמת.
- **la2, שאלה 3 (אפס כישלונות):** נלמד ב-What Came Before the Success? על פורטל של מובילים ועל 30 יום, לא 14. הפריימר נותן רק את השיטה ודוגמה של מנעול. לא מופיעה בו התשובה.
- **ac1 (האות המכריע של הבוס):** נלמד במעבדה משלו, Which Branch Applies?, על מכשירים ועל share של הפצת תוכנה, לא על מקור אחד שמתחבר בשם כמה אנשים. המלכודות של הבוס נלמדות על דוגמה אחרת: לטפל בכל החמישה ולסגור, לטפל באחד, לחכות לבוקר. גם תוצאה הפוכה נלמדת: בסיבוב הראשון השער דווקא נפתח.
- **q2 (מה מפריד סטייה תקינה משגויה):** נלמד ב-Sign It Off, or Send It Back? על חמישה טיקטים של Greenhithe. במקור החדר q2 באה לפני הקריאה שמלמדת אותה, ולכן המעבדה יושבת על q2 עצמה.
- **שאלת הביניים של r3 (למה זו לא סטייה):** נלמד בשורת היציאה של PB-22 ובנקודה על exit line בפריימר של Which Branch Applies?. PB-17 בלי שורת יציאה מראה את ההפך: שם זו סטייה אמיתית.
- **f1 (ה-ASN):** המונח נלמד ב-Four Words for the Ticket עם הדוגמה AS64500. הערך נקרא מהרשומות הנבחנות, ולא מופיע באף מעבדה.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Red Binder" | כניסה | תחנה 1 |
| Chapter 2: "Written in March" | אחרי The Binder | תחנה 2 |
| Chapter 3: "One Click Away" | אחרי Walk the Page | תחנה 3 |
| Finale: "The Page Gets Rewritten" | אחרי The Call | החדר הבא |
