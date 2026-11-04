# תסריט חדר 15: Cyber Kill Chain

**שם המבצע:** Operation Broken Link
**רמה:** מתחילים
**העולם:** Brightwater Utilities (חברה בדויה): טיהור מים ל-1.2 מיליון איש, ורשת הנדסית שאסור לה להחשיך.
**המנטורית:** Ayla Demir, ראש צוות ציד האיומים.

## סיפור הרקע
ב-09:47 הבוקר חיישן DNS סימן תחנת עבודה ששואלת את אותו דומיין מוזר את אותה שאלה, כל חמש דקות. Ayla לא שואלת "מה זה?". היא שואלת "עד איפה בשרשרת הם הגיעו?". עוברים כאן על שבע החוליות, עוקבים אחורה אחרי החדירה עד המייל הראשון, ומוצאים איפה השרשרת נשברת.

## העולם התלת-ממדי: Chain Links
שבע חוליות שזורות זו בזו נמתחות בקשת מעל הרצפה, חוליה לכל שלב. כדור תקיפה מתגלגל מחוליה לחוליה ומדליק כל חוליה שהוא עובר. לצד כל חוליה עולה מגן. אחר כך חוליית ה-C2 מתנפצת, והכדור נעצר לפני החוליה האחרונה. מעל הכול מסתובב מודל היהלום (Diamond Model) עם ארבע פינות: ADVERSARY, ‏INFRA, ‏CAPABILITY ו-VICTIM.

## סדר המשימות
r1 | r2, q1, q3 | r3, q2, la1 | o1, q4

השאלה q3 (על Installation) עברה לתחנה של r2, ליד q1.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Seven Links | r1 | **The Heist Chain**: התאמה בין שלבי שוד בנק לשלבי השרשרת |
| 2 | Walk the Chain | r2, q1, q3 | **Map Brightwater's Intrusion**: מיפוי ממצאי החקירה לשבע החוליות. **Hunt the Foothold**: ‏reg query על מפתח Run, ‏dir ו-certutil -hashfile ב-cmd |
| 3 | Break the Chain | r3, q2, la1 | **Back Up the Chain**: מעקב לאחור מ-DNS (C2), דרך Sysmon 13 (Installation) ו-Sysmon 1 (Exploitation), ועד שער הדואר (Delivery). תרגול **Anatomy of a PAN-OS Threat Log** (‏sinkhole), ואחריו הרשומה הנבחנת |
| 4 (בוס) | The Debrief | o1, q4 | תרגול **The Diamond Beside the Chain**: הצבת הראיות על ארבע הפינות של מודל היהלום |

**הפרדה מהשאלות הנבחנות:**
- החדירה היא loader מסוג ISO/LNK, עם עוגן במפתח Run ו-C2 ב-DNS TXT.
- אין בחדר מאקרו (q1), אין scheduled task בשם WindowsUpdateHelper ‏(q3), ואין beacon של 30 שניות אל updates.microsoft-cdn-services.net (q2, la1).
- ההתאמה עוסקת בשוד ולא בסדר השלבים (o1).
- דף מודל היהלום לא מונה את מגבלות המודל (q4).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Every Five Minutes" | כניסה | תחנה 1 |
| Chapter 2: "Seven Links" | אחרי Seven Links | תחנה 2 |
| Chapter 3: "Back to the First Email" | אחרי Walk the Chain | תחנה 3 |
| Finale: "The Link That Broke" | אחרי הבוס | החדר הבא: Firewall and Network Security |
