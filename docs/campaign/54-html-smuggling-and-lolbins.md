# תסריט חדר 54: HTML Smuggling and LOLBins

**שם המבצע:** Operation Special Delivery
**רמה:** מתקדם
**העולם:** Marrow & Hale LLP (משרד עורכי דין בדוי): 300 עורכי דין, 40,000 קבצים מצורפים בשבוע, ויום עבודה שבנוי על פתיחת מסמכים ממי שלא מכירים.
**המנטור:** Zanele Mokoena, Detection Engineer. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ה-gateway סורק כל קובץ, וה-allowlisting עוצר כל דבר לא מוכר. על הנייר שום דבר לא נכנס. הטיעון של Zanele: שני הטריקים הכי טובים של השנים האחרונות לא צריכים לנצח אף אחת מהבקרות. אחד בונה את הקובץ אחרי ה-gateway, והשני מריץ אותו דרך תוכנה שכבר סומכים עליה.

## המכניקה הייחודית של החדר
**Hold the Command Line:** אותן ארבע תוכנות רצות על כל המחשבים, ושורות פקודה נופלות בזמן אמת. הלומד חוסם או מעביר, ורואה גם את תהליך האב. אותה תוכנה, פעם בעבודתה הרגילה ופעם בעבודה של התוקף, וחסימת התקנה אמיתית עולה כמו התקפה שעברה.

## העולם התלת-ממדי: Special Delivery
- קשת סריקה שרואה רק text/html, וטקסט שעובר דרכה.
- מחשב נייד, ומעליו הביטים מתחברים לקובץ bundle.iso.
- ארבעה עמודים חתומים עם חותם ירוק: mshta, ‏regsvr32, ‏rundll32, ‏msiexec.
- רוכב אדום שנאחז בעמוד השלישי, ולוח CommandLine שחושף אותו.
- מגן חוק וקונסולה עם שלושת חלקי השאילתה.

## סדר המשימות
r0, r1, r2, r3, q1 | r4, r5, r6, q2 | r7, m1, o1, q3 | r8, la1, f1 | r9, ac1, q4

(f1 זז מיד אחרי la1 כי הוא קורא את אותו לוג. שאר הסדר נשאר.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Attachment | r0, r1, r2, r3, q1 | **Your Controls Against Theirs** (duel), **Find the Payload** (hotspot), **Whose Tradecraft Is This?** (lineup) |
| 2 | Signed and Sealed | r4, r5, r6, q2 | **Crack the Family** (codebreak) |
| 3 | Two More Doors | r7, m1, o1, q3 | **Hold the Command Line** (intercept) |
| 4 | What the Telemetry Shows | r8, la1, f1 | הלוג הנבחן |
| 5 (בוס) | The Right Ten | r9, ac1, q4 | **Fix the Rule Before It's Switched Off** (defuse) |

**הפרדה מהשאלות הנבחנות:**
- שום ערך מהרשומות של Thornfield: אין 198.51.100.77, ‏185.221.20.44, ‏invoice_svc.sct, ‏CHG-88413, ‏ccmexec.
- אין שחזור של סדר השרשרת (o1), של השימוש היומיומי של כל תוכנה (m1) או של הקישור דרך Zone.Identifier ‏(q4).
- ה-intercept משתמש בכתובות אחרות ובשורות פקודה אחרות, וה-msiexec שלו לא מכיל את ארבע האפשרויות של q3.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "40,000 Attachments" | כניסה | תחנה 1 |
| Chapter 2: "Nothing Crossed the Wire" | אחרי The Attachment | תחנה 2 |
| Chapter 3: "Signed and Sealed" | אחרי Signed and Sealed | תחנה 3 |
| Chapter 4: "Same Program" | אחרי Two More Doors | תחנה 4 |
| Finale: "Special Delivery" | אחרי הבוס | החדר הבא |
