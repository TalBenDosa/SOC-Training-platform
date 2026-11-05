# תסריט חדר 56: Exchange Online Security

**שם המבצע:** Operation Reply All
**רמה:** בינוני
**העולם:** Thistledown Seed Co-op (קואופרטיב זרעים בדוי): 212 תיבות דואר, 4,000 חקלאים, וכל הזמנה, חשבונית ותשלום עוברים במייל.
**המנטור:** Sefa Mensah, Mail Security Engineer. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
כסף הזרעים של האביב הקודם הלך לחשבון בנק לא נכון. הבקשה ישבה על שרשור אמיתי, עם שם של עמית אמיתי. בלי וירוס ובלי אזעקה: מספיק היה מייל.

## המכניקה הייחודית של החדר
**Work the Thread:** קונסולה בסגנון Exchange admin center, סקין חדש של `portal`: Message trace עם חלונית פרטים מימין ו-Message events, ואז Audit. הלומד מגלה שהמייל נקי כי תיבה אמיתית שלחה אותו, יוצא מהמייל אל לוג הביקורת, ומוצא את חוק ה-inbox.

## העולם התלת-ממדי: Reply All
- דרך דואר על הרצפה: צומת שולח, שתי קשתות סריקה (EOP, DEFENDER) וארון MAILBOX.
- שלושה חותמות תלויים מעל הדרך (SPF, DKIM, DMARC) שננעלים בזה אחר זה.
- צינור אדום יוצא מהארון אל תיקייה קבורה (RSS FEEDS), ומפסיק לזרום כשהתחנה נסגרת.
- טרמינל Treasury עם קו חי לחשבון רחוק, שנעצר עם סיום הבוס.

## סדר המשימות
r1 | r2, q1 | r3, q2, q3 | la1, f1

(q1 זז אחרי r2 כי הוא על Authentication-Results.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Mailbox | r1 | **Walk the Message In** (pathway), **Which Layer Caught It?** (rush) |
| 2 | The Seal | r2, q1 | **Check the Seals** (simulate), **Defuse the Header** (defuse) |
| 3 | The Silent Rule | r3, q2, q3 | **Hold Back the Rules** (intercept), **Work the Thread** (portal, Exchange) |
| 4 (בוס) | The Wire | la1, f1 | הלוג הנבחן |

**הפרדה מהשאלות הנבחנות:**
- אין דומיין חיקוי ‏(q2, ‏la1, ‏f1), אין SCL -1, ואין כותרת spf=pass dkim=pass dmarc=fail ‏(q1). היישור נלמד על דוגמה אחרת: SPF עבר לדומיין של ספק, בלי DKIM, ו-DMARC נכשל.
- אין העברה ברמת התיבה ‏(q3): בקונסולה רק חוקי inbox, ו-Set-Mailbox לא מופיע.
- אין ניוזלטר מועבר (checkpoint של r2) ואין 185.234.91.7.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Paid in Full" | כניסה | תחנה 1 |
| Chapter 2: "The Road In" | אחרי The Mailbox | תחנה 2 |
| Chapter 3: "Clean Mail" | אחרי The Seal | תחנה 3 |
| Finale: "Reply All" | אחרי הבוס | החדר הבא |
