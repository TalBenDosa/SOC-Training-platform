# תסריט חדר 27: Email Security

**שם המבצע:** Operation Postmark
**רמה:** בינוני
**העולם:** Rivermead Construction (חברת בנייה בדויה): מאות קבלני משנה, אלפי חשבוניות, ותיבת דואר שמזיזה כסף אמיתי.
**המנטורית:** Hannah Cole, אנליסטית אבטחת דואר.

## סיפור הרקע
כל מייל נושא בכותרות שלו יומן מסע, ושלושה חותמות שאומרים מי באמת שלח אותו. רוב האנשים לא מסתכלים על אף אחד מהם. Hannah קוראת אותם כל היום. היא תראה לך מאיפה הודעה באמת הגיעה, מה ה-DNS אומר על השולח, ואיך נראה שרשור (thread) שנחטף.

## העולם התלת-ממדי: Postmark
- מעטפה עפה ממגדל ממסר אחד למשנהו, ובכל קפיצה מקבלת חותמת Received.
- בשער ביקורת נלחצות עליה שלוש חותמות: SPF, ‏DKIM ו-DMARC. לידו תמרור DNS עונה ברשומות TXT.
- שרשור הודעות תלוי כשרשרת כרטיסים, והאחרון אדום, עם קרס.
- בסוף, חץ תשלום טס אל כספת ונעצר במגן.

## סדר המשימות
r1 | r2, q1, q2, q4 | r3, q3 | la1, flag1 (השאלה q4 על DMARC הוקדמה אל r2)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Travel Log | r1 | **Read the Travel Log**: כותרות Received מלמטה למעלה, ‏ESMTPSA ופער הזמנים |
| 2 | Three Seals | r2, q1, q2, q4 | **Ask DNS About the Sender**: ‏dig TXT על SPF ‏(-all ו-include), ‏DMARC ‏(p=quarantine ו-adkim=s), ‏DKIM ו-MX |
| 3 | The Con | r3, q3 | **The Hijacked Thread**: ‏hotspot על Reply-To עם I במקום l, החלפת פרטי בנק ודחיפות, בתוך תיבה אמיתית |
| 4 (בוס) | The Wire Request | la1, flag1 | תרגול **Anatomy of an Email Event** (‏EmailEvents של Defender: ‏SenderFromAddress מול SenderMailFromAddress, ‏CompAuth ו-Junked) |

**הפרדה מהשאלות הנבחנות:**
- דף הכותרות לא משווה d= של DKIM ל-From (q1), ולא קורא spf=fail ‏(q2).
- ה-dig לא מעריך alignment בהעברה (q4).
- השרשור החטוף שייך לספק, ולא לבקשת העברה של CFO שצריך לסווג (q3).
- התרגול הוא רשומת Defender, ולא ה-corp-secure.com של la1 או דומיין ה-SPF שלו (flag1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Every Email Has a Travel Log" | כניסה | תחנה 1 |
| Chapter 2: "What the Seals Prove" | אחרי The Travel Log | תחנה 2 |
| Chapter 3: "A Real Mailbox, a Fake Request" | אחרי Three Seals | תחנה 3 |
| Finale: "Two Senders" | אחרי הבוס | החדר הבא: Protocols Masterclass |
