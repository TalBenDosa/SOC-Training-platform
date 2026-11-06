# תסריט חדר 100: OSINT Fundamentals

**שם המבצע:** Operation Open Source
**רמה:** בינוני (כל ה-primers פתוחים)
**העולם:** Larkhill Veterinary Group (רשת וטרינרית בדויה): ארבע עשרה מרפאות, בית חולים אחד למקרי לילה, ודלפק קבלה ב-Ashcombe שקיבל ביום שלישי מייל מיודע מדי.
**המנטור:** Maren Abiodun, OSINT Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שלישי מגיע לדלפק הקבלה ב-Ashcombe מייל שמזכיר את שרת ההדמיה של הרשת, את חומת האש שלה ואת האנשים שלה. אף אחד מבפנים לא מסר את הפרטים האלה. לפי Maren הכול היה פומבי, והמשימה לפני המייל הבא היא לראות את Larkhill בדיוק כמו שהשולח ראה אותה: ממקורות פתוחים בלבד, בלי לגעת בכלום. בסוף השבוע מחשב נייד מתחיל לדבר עם שרת שאיש לא מכיר, וההחלטה צריכה להתקבל מנתונים ציבוריים בלבד.

## המכניקה הייחודית של החדר
- **See Yourself as the Attacker Does:** הלומד ממפה את החשיפה של החברה עצמה. מסכי `evidence` של חיפוש בלוגי Certificate Transparency, מודעת דרושים שמפרטת את ה-stack, חיפוש ציבורי של כתובות שדלפו ומטא-דאטה של תמונה. בכל מסך הוא מסווג את הקטגוריה וקורא מה נחשף.
- **Crack the Search Operators:** `codebreak` על אופרטורי חיפוש, כולם על הדומיין של Larkhill עצמה.
- **הקו החוקי והאתי:** `spotdiff` של תוכנית האיסוף של Maren מול העותק של הקבלן, שבו שלוש שורות עברו מקריאה למגע, כולל כניסה לפאנל עם סיסמה שנמצאה. `deduce` על דף canary שמראה מה היעד באמת רואה.
- **אין כאן pivoting:** חדר 59 מכסה IOC pivoting. כאן מופיע רק שם הטכניקה, כי q2 שואל עליו, וזו לא מכניקה בחדר.

## העולם התלת-ממדי
אי קמפוס (`facility`) של Larkhill Veterinary Group: ארבעה מבנים לפי התחנות, אף מבנה לא מאחורי מבנה אחר ולא לפני ה-Hub. עיר ה-Hub נושאת את שם החברה.

## סדר המשימות
r1 | r2, q2 | r3, q1, q3 | la1, flag1, q4

הסדר שונה מהמקור, שבו כל הקריאות באות קודם. עכשיו כל שאלה יושבת אחרי הקריאה שלה: q2 על הכלים עובר אחרי r2, ו-q1 ו-q3 נשארים אחרי r3. הקריאות שומרות על סדרן. הדגל flag1 אומר "the log above", ו-la1 נשאר מיד לפניו, אז הניסוח עדיין נכון. אין בחדר הפניה מסוג "Log Analysis N".

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Footprint | r1 | **See Yourself as the Attacker Does** (evidence) |
| 2 | The Toolkit | r2, q2 | **Which Tool Answers It?** (match), **Anatomy of a Domain Record** (anatomy), **Crack the Search Operators** (codebreak) |
| 3 | The Line | r3, q1, q3 | **Find Where the Plan Crosses the Line** (spotdiff), **Who Touched the Canary?** (deduce), **What Did We Publish?** (worksheet) |
| 4 (בוס) | Read Only | la1, flag1, q4 | **Anatomy of a Scanner Record** (anatomy), **Same Ports, Different Host** (worksheet) |

משחקי ארקייד בחדר: codebreak + deduce + spotdiff בלבד.

**הפרדה מהשאלות הנבחנות:**
- **r1 (שאלת ביניים, קטגוריית Infrastructure):** ה-primer של See Yourself as the Attacker Does מגדיר כל קטגוריה לפי הנושא שלה, והמסכים ממיינים לוג תעודות, מודעת דרושים, חיפוש כתובות שדלפו ותמונה. אין במעבדה בעלות על IP, פורטים או תעודה של שרת חיצוני. הדוגמה ב-primer היא שם משתמש של בעלת מאפייה.
- **r2 (שאלת ביניים, WHOIS):** Anatomy of a Domain Record מציג רשומה של הדומיין של Larkhill משנת 2011 כשדות עם תווית, ולא שואל איזה כלי עונה. שאלת זיכרון טהורה. Which Tool Answers It? לא כולל WHOIS.
- **q2 (שם הטכניקה):** השם מופיע בשורת ה-lesson של Crack the Search Operators, על חיפוש בדומיין של Larkhill. Which Tool Answers It? מלמד מה Censys מחזיק. אין במעבדה תעודת פישינג ואין שאלה על השם.
- **q1 (הצעד הראשון):** Find Where the Plan Crosses the Line מלמד את השאלה "איפה הבקשה נוחתת". הצעדים הפעילים במעבדה הם zone transfer, מייל בדיקה וכניסה לפאנל, לא סריקת פורטים, לא סריקה ציבורית ולא חסימה. VirusTotal מופיע בשורה אחת בתוכנית, ו-ThreatFox בשורה אחרת, כמדד למעקב אחרי C2.
- **q3 (נראות הסריקה):** What Did We Publish? מלמד את שלוש רמות הנראות ואת הסוד בתוך URL על קישורים של עובדי Larkhill עצמם, לא על קישור פישינג עם מספר נמען. Who Touched the Canary? מלמד active by proxy על דף canary של Larkhill. הדוגמה ב-primer היא כרטיס להופעה.
- **la1 שאלה 1 (סוג השרת):** הסימן המכריע נלמד במעבדה משלו, Same Ports, Different Host: חמש רשומות עם os ופורטים כמעט זהים (22 ו-443, לא 80, 443 ו-8080), והתג הוא שקובע מהו המארח ומה המשמעות של חיבור ממחשב ארגוני. השאלות שואלות על העמודה, על honeypot ועל vpn. Anatomy of a Scanner Record הוא שרת Windows נשכח של Larkhill עם התג eol-product על פורט אחד, וה-primer שלו מגדיר מהו Tor ומהו relay, בלי לדון באפשרויות השאלה. כל הערה מתארת מה השדה מציג ולא שופטת.
- **la1 שאלה 2 (הצעד הבא):** הידע מגיע מ-Find Where the Plan Crosses the Line, שבו VirusTotal ו-ThreatFox יושבים בשורות נפרדות, כדי שלא יהיה אפשר להתאים את האפשרות הנכונה לפי צמד השמות. השדה org מתואר רק כמי שמרחב הכתובות מוקצה לו.
- **flag1 (שם התעודה):** השדה ssl.cert.subject.cn באנטומיה מלמד מה זה CN ומה זה wildcard, על השם של oldbooking. התשובה לא מופיעה בשום מעבדה.
- **q4 (הצעד הפסיבי לגמרי):** הסימן המכריע נלמד בשתי מעבדות נפרדות: Who Touched the Canary? (האם משהו הגיע ליעד) ו-What Did We Publish? (מי לומד משהו חדש). הגיליון עוסק ב-PDF פנימי של Larkhill, ושואל אם הקובץ יצא, לא על קובץ חשוד ממייל.
- **OPSEC:** ה-primer של Who Touched the Canary? מגדיר אותו. VPN מופיע רק כנתון על הצעד של Pryce, בלי קביעה.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "What the Email Knew" | כניסה | תחנה 1 |
| Chapter 2: "Nobody Leaked It" | אחרי The Footprint | תחנה 2 |
| Chapter 3: "A Keen Contractor" | אחרי The Toolkit | תחנה 3 |
| Finale: "A Smaller Footprint" | אחרי Read Only | החדר הבא |

הערות לסרטונים:
- **Intro:** Maren, המרפאה ב-Ashcombe והמייל שידע יותר מדי. לא מראים מסך ולא כלי.
- **Chapter 2:** מנהל ה-IT מחפש מי מבפנים דיבר, והתשובה של Maren: אף אחד. לא מראים איך זה נמצא.
- **Chapter 3:** קבלן נלהב רוצה ללכת רחוק יותר, והתשובה של Maren היא לא. לא מראים מה בדיוק הוצע.
- **Finale:** Larkhill מקטינה את מה שהיא חושפת, והמרפאה ב-Ashcombe חוזרת לשגרה. סיפור בלבד, בלי פסק הדין של המשימה הנבחנת.
