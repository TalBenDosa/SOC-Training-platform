# תסריט חדר 51: TCP/IP Internals for Analysts

**שם המבצע:** Operation Wire Level
**רמה:** מתקדם
**העולם:** Kelvin Point Hosting (חברת אחסון בדויה): שלושה אולמות נתונים, 1,400 שרתי לקוחות, ו-tap על כל קישור ליבה.
**המנטורית:** Anneke Visser, אנליסטית רשת ראשית.

## סיפור הרקע
בחודש שעבר לקוח נשבע שלוגי ה-firewall שלו נקיים. החבילות אמרו אחרת, ו-Anneke הוכיחה את זה ב-11 דקות. היא לא מתחילה מדשבורדים אלא מדגלים, TTL ומוני בתים, כי אלה החלקים של חיבור שאף אחד לא חושב לזייף.

## המכניקה הייחודית של החדר
**הליכה במכונת המצבים של TCP:** הלומד מוביל socket של שרת צעד אחר צעד על מפה של מצבי TCP, מ-LISTEN עד CLOSED. צעד שגוי עולה בחיים ומסביר למה המצב הזה שייך לצד השני. כך המשחק עצמו הוא הנושא.

## העולם התלת-ממדי: Wire Level
- שני ארונות (CLIENT, ‏SERVER) מחוברים בחוט, וחבילות שעוברות בקצב של לחיצת יד.
- שורת מתגי דגלים: SYN, ‏ACK, ‏FIN, ‏RST, ‏PSH, ‏URG.
- שורת ארונות HALL 2 עם בדיקה אדומה שקופצת לאורכה.
- טבעות TTL שיורדות בכל קפיצה.
- מסך לכידה עם retransmissions.
- ענן שרתים שמתפרץ ב-resets, ומגן הכרעה.

## סדר המשימות
r1, r2, o1, q1 | r3, m1, q2, q3 | r4, la2, f1 | r5, r6, r7, la1, qf1 | ac1

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Three-Way Handshake | r1, r2, o1, q1 | **Walk the State Machine** (pathway) |
| 2 | Scan Signatures | r3, m1, q2, q3 | **Who's Probing Hall 2?** (deduce) |
| 3 | Fingerprints | r4, la2, f1 | **Fingerprint Panel** (defuse) |
| 4 | Flow or Packet | r5, r6, r7, la1, qf1 | **Flow or Packet?** (rush), **Why Won't It Connect?** (pcap) |
| 5 (בוס) | RST Bursts | ac1 | הכרעה |

**הפרדה מהשאלות הנבחנות:**
- ההליכה היא בצד השרת, לא מגיעה ל-TIME_WAIT (checkpoint של r1) ולא מסדרת סגמנטים (o1).
- החשודים בלי שמות טכניקות (m1), בלי מצבי Zeek ‏(q2, ‏checkpoint של r2) ובלי תשובות של פורט סגור (q1).
- ה-fingerprints בלי flow exports ‏(checkpoint של r4) ובלי הסשנים הנבחנים (la2, ‏f1).
- הבליץ בלי ערכי conn_state ‏(la1, ‏qf1) ובלי health checks ‏(ac1).
- הלכידה היא מארח חסום, בלי שאלה על סוגי מסננים (checkpoint של r7).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Eleven Minutes" | כניסה | תחנה 1 |
| Chapter 2: "Handwriting" | אחרי The Three-Way Handshake | תחנה 2 |
| Chapter 3: "The Header Tells" | אחרי Scan Signatures | תחנה 3 |
| Finale: "Packets Don't Lie" | אחרי הבוס | החדר הבא |
