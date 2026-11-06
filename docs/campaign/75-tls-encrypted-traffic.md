# תסריט חדר 75: TLS & Encrypted Traffic Analysis

**שם המבצע:** Operation Sealed Room
**רמה:** מתקדם (כל ה-primers מקופלים, `fold: true`)
**העולם:** Tessellate Payments (מעבד תשלומים בדוי): תשלומים לסוחרים בחצי יבשת, וקומה נעולה אחת שבה נבנית ריצת הסליקה של יום שישי.
**המנטור:** Ruaridh Banerjee, Network Security Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
כל מה שיוצא מקומת הסליקה הוא TLS, ולפי מדיניות אף אחד לא מפענח אותו. בבניין קוראים לקומה הזאת the Sealed Room. השבוע לפטופ אחד בקומה התחיל לשמור על לוח זמנים שאף אחד לא נתן לו, ו-Ruaridh לא יכול לקרוא ממנו בייט אחד. אי אפשר לקרוא את המכתב, אבל אפשר לקרוא את המעטפה, והריצה יוצאת ביום שישי.

## המכניקה הייחודית של החדר
**Read What Encryption Leaves:**
- **Read the Envelope:** לכידה של שש סשנים שבה ה-SNI, שדות התעודה, JA3 ו-JA4 גלויים, וחלונית ה-payload נשארת ריקה בכל פקטה. הלומד רואה ב-TLS 1.2 את התעודה עוברת בגלוי, ב-TLS 1.3 את התעודה נעלמת, וב-ECH את ה-SNI האמיתי נאטם.
- **Beacon or Telemetry?:** מעבדת `tune` עם שני חוגים, פיזור מרווחים וגיל תעודה בראייה ראשונה, שמפרידה בין C2 לטלמטריה. אף חוג לא מספיק לבד, ו-beacon על דומיין מיושן עובר גם את הכלל הטוב ביותר.

## העולם התלת-ממדי
אולם קלפים (`facility`, hall) עם `core: "globe"`: חמישה קלפים לפי התחנות, ועל הדוכן גלובוס שמסמל את התעבורה שיוצאת מהקומה. עיצוב בצבעי חותם שעווה.

## סדר המשימות
r1, o1, r2, q1 | r3, r6, la2 | r4, q2, la1, f1, qf1 | r5, q3, m1 | ac1

הסדר המקורי שם את כל הקריאות בהתחלה, ולכן אי אפשר לחלק אותו לתחנות. o1 בא אחרי r1 כי הוא מסדר את הלחיצה ש-r1 מלמד. la2 צריך גיל תעודה מ-r2 ו-JARM מ-r3. q2 שוקל אותות שרק r4 מלמד. f1 ו-qf1 אומרים במפורש שהם באים אחרי Log Analysis 1. m1 צריך pinning, ולכן בא אחרי r5.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Handshake | r1, o1, r2, q1 | **Read the Envelope: Six Sealed Sessions** (pcap), **The TLS 1.3 Flight: Where the Seal Starts** (sequence), **Anatomy of a Certificate Record** (anatomy), **Which Certificate Flags Mean Anything?** (simulate), **Name It from the Envelope** (codebreak) |
| 2 | The Fingerprint | r3, r6, la2 | **Anatomy of an ssl.log Line** (anatomy), **One Browser, Many JA3s** (worksheet), **Which Fingerprint for This Job?** (sort), **Does the Hello Fit the Host?** (sort), **First Contact: What Explains It?** (queue) |
| 3 | The Beacon | r4, q2, la1, f1, qf1 | **Beacon or Telemetry? Timing and Certificate Age** (tune), **The Shape of a Check-In** (worksheet), **Escalate or Baseline: One Signal or Several?** (intercept), **From Envelope to Process: The Order of Work** (sequence), **Thresholds That Would Still Catch It** (worksheet) |
| 4 | The Proxy | r5, q3, m1 | **What the Proxy Can Open** (simulate), **One App Fails at the Proxy** (worksheet) |
| 5 (בוס) | The Sealed Room | ac1 | **Certificate Flags, Three Verdicts** (queue), ואז ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- שאלת הביניים של r1 (סבב אחד ב-TLS 1.3): ה-primer של **Read the Envelope** מציג את העובדה כנתון, והיא מופיעה גם כהערה על פקטה 17 ובתרגיל **The TLS 1.3 Flight**. אף יעד לא שואל כמה סבבים יש. ה-0-RTT מופיע בהערת הסיום של ה-sequence.
- o1 (סדר TLS 1.2): הסדר גלוי כנתון בפקטות 4 עד 10 של הלכידה, ואף יעד לא שואל עליו. ה-sequence מסדר את TLS 1.3, לא את 1.2.
- q1 (למה SNI גלוי): היעד `shared` בלכידה מראה כתובת IP אחת עם שני אתרים ושתי תעודות, וה-`why` מסביר את הסיבה. אין דיון בניסוחי התשובות של q1.
- שאלת הביניים של r2 (תעודה עצמית וטרייה): התרחיש `fresh` ב-**Which Certificate Flags Mean Anything?** עובד על תעודה בת שלושה ימים עם תוקף של עשר שנים, לא על תעודה בת יום. אותה תעודה נקראת גם ביעד `age` של הלכידה.
- שאלת הביניים של r3 (JA3 מול JARM): **Anatomy of an ssl.log Line** מלמד שדה-שדה, והסיכום מסביר למה אין JARM בלוג. **Which Fingerprint for This Job?** מיישם על שמונה משימות עבודה, בלי הגדרות.
- la2 שאלה 1 (גיל מול תקופת תוקף): היעד `age` בלכידה והתרחיש `fresh`, עם תקופה של עשר שנים ולא שנה. ה-primer של ה-tune מגדיר גיל בראייה ראשונה.
- la2 שאלה 2 (למה JARM): **Anatomy of an ssl.log Line** ו-**Which Fingerprint for This Job?**, עם 40 כתובות שאף מארח לא פנה אליהן, לא חיבור ראשון של שרת build.
- la2 שאלה 3 (תגובה מאוזנת): **First Contact: What Explains It?** עם שרת תשלומים, שרת קפיצה ושרת דוחות, בפורטים 9443 ו-443. אין שרת build, אין 8443 ואין ci-artifact-sync.
- q2 (האות החלש ביותר לבד): התרחיש `print` ב-simulate והפריט `i6` ב-intercept מלמדים שתעודה עצמית לבדה כמעט לא אומרת כלום. `i1` מלמד SNI מול בעלות על IP על טווח VPS, לא על ספק ביתי. `i3` מלמד התאמת טביעה לברירת מחדל ידועה, ו-`i2` עם **The Shape of a Check-In** מלמדים גודל קבוע. אף מעבדה לא מדרגת את ארבעת האותות של q2.
- la1 שאלה 1 (beacon מול CDN): **Beacon or Telemetry?** ו-**The Shape of a Check-In**, על 300 שניות ולא 60, על sync.ledgerfont.example ו-203.0.113.118, בלי 96 סשנים, בלי 5.1 ובלי 4.2.
- la1 שאלה 2 (גודל כאות נפרד): השאלה האחרונה ב-**The Shape of a Check-In**, על סוכן גיבוי עם טיימר וגדלים משתנים. שם גם נלמד שתגובה גדולה היא משימה מהמפעיל.
- la1 שאלה 3 (הצעד הבא): **From Envelope to Process: The Order of Work** על מקרה ישן בצוות Legal. הערת הסיום היא שורה אחת: הרשת לא יכולה לנקוב בתהליך, והמעבדה לא עוברת על אפשרויות התשובה.
- f1 (שם ה-cipher): היעד `cipher` בלכידה ו-**Anatomy of an ssl.log Line** מלמדים היכן השדה נמצא. הערכים הם ECDHE עם AES-128-GCM ו-AES-256-GCM, לא TLS_RSA_WITH_AES_128_CBC_SHA.
- qf1 (ספים): **Thresholds That Would Still Catch It** על פורט 9443, רצפה 200 ותקרה 40, כולם מחוץ לטווחי התשובות. ה-primer מלמד רצפה מתחת ותקרה מעל, והשאלה האחרונה מלמדת ש-JA3Hash משותף הוא נקודת pivot, ושמעקב אחרי רוטציה דורש `by SourceIp, JA3Hash` עם `dcount(DestinationIp)`.
- שאלת הביניים של r5 ו-q3 (pinning): **What the Proxy Can Open** על לקוח הודעות, ו-**One App Fails at the Proxy** על tokenvault.exe בצוות Treasury. השאלה על CA שפג תוקפו מלמדת להבדיל בין יישום אחד שנכשל לבין פרוקסי מת.
- m1 (התאמת מונחים): כל מונח נלמד בנפרד. SNI בלכידה, JA3 ו-JA3S ו-JARM באנטומיה ובמיון, תעודה עצמית ב-simulate של r2, ו-pinning ב-simulate של r5. אף מעבדה לא משתמשת בניסוחי הצד הימני של m1.
- ac1 (benign true positive): האות המכריע נלמד במעבדה משלו, **Certificate Flags, Three Verdicts**, עם ארבע התראות ושלושה פסקי דין: סורק פגיעויות מאושר שנגע בתעודה שפג תוקפה בחלון שהוזמן לו, כתובת בלי בעלים, חיישן שאיבד את שורש ה-CA הפנימי, ומארח מוכר שההיסטוריה שלו נשברה. המקרה התמים הוא סורק ולא מכשיר עם תעודה עצמית, ואין מכשיר גיבוי, אין 8007, אין 01:00 בלילה ואין 244 מארחים.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Sealed Room" | כניסה | תחנה 1 |
| Chapter 2: "Two Stacks, One Laptop" | אחרי The Fingerprint | תחנה 3 |
| Chapter 3: "The Answer Is Still Sealed" | אחרי The Proxy | תחנה 5 |
| Finale: "Friday, Six O'Clock" | אחרי The Sealed Room | החדר הבא |
