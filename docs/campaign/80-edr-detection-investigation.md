# תסריט חדר 80: Investigating an EDR Detection

**שם המבצע:** Operation Process Tree
**רמה:** מתקדם
**העולם:** Kilnworth Ceramics (יצרנית קרמיקה בדויה): 620 עובדים, שני מפעלים, וספר מתכוני זיגוג שנבנה במשך ארבעה דורות.
**המנטור:** Mateusz Oyelaran, EDR Engineer. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
בלילה שבין ראשון לשני, במשמרת של מעבדת הזיגוג, מישהו חיפש פרופילי שריפה לתנור ופתח דיסק וירטואלי מאתר מתחזה. בשעה 06:52 ה-EDR תפס תהליך ששלח את ספר המתכונים החוצה, הרג אותו וסימן Critical. מנהל המפעל שמע "נהרג" ומבחינתו זה נגמר. הכלל של Mateusz אחר: מתחילים מהמקום שבו ההתראה נורתה, ומטפסים עד המקום שבו הכול התחיל.

## המכניקה הייחודית של החדר
- **Past the Loudest Node:** קונסולת EDR שבה החיישן כבר הרג את הצומת הרועש. הלומד קורא מה הכלי באמת עשה, מטפס בעץ התהליכים אל התהליך החי הראשון ומשם אל שורש האירוע, עושה pivot לקובץ הנכון, סורק את הצי, מוצא מחשב שקט שאף התראה לא נורתה עליו, פוסק ורק אז מכיל את שני המחשבים. חדרים 39 ו-40 מציגים את המוצרים. החדר הזה עוסק בשיטה: שורש האירוע, לא הצומת הרועש.
- **What Still Sees It:** דו-קרב. התוקף משחק מהלך הסתרה, והלומד משחק את הטלמטריה שעדיין תופסת אותו. כל קלף הוא דבר שהחיישן באמת רושם.

## העולם התלת-ממדי
אי קמפוס (`facility`) של Kilnworth: חמישה מבנים לפי התחנות, מפוזרים בקשת סביב ה-Hub בלי מבנה מאחורי מבנה ובלי מבנה מול ה-Hub. עיר ה-Hub נושאת את שם החברה.

## סדר המשימות
שונה מהסדר המקורי: רק `edr-qf1` זז לסוף, כדי שהבוס יהיה הציד שהלומד כותב בעצמו.
r1, r2, q1, m1 | r3, o1, r4, q2, la1 | r5, q3, r6, ac1 | r7, f1, q4, q5 | qf1

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Detection | r1, r2, q1, m1 | **Who Could Have Told You That?** (sort), **Anatomy of a Detection** (anatomy), **Anatomy of One Process Reaching Into Another** (anatomy), **Did It Run?** (worksheet) |
| 2 | Up the Tree | r3, o1, r4, q2, la1 | **Past the Loudest Node** (portal), **What the Shortcut Cost** (match), **Everyday, Anomaly or Not Enough?** (sort), **What Still Sees It** (duel), **Whose Hand, Whose Memory?** (worksheet) |
| 3 | The Siblings | r5, q3, r6, ac1 | **Three Tickets or One Story?** (worksheet), **Same Rating, Different Truth** (queue) |
| 4 | The Pivot | r7, f1, q4, q5 | **A Third Host at 14:20** (trace), **What Each Response Costs** (simulate), **Cut Ahead of It** (outbreak) |
| 5 (בוס) | The Last Branch | qf1 | **Which Way Is Up?** (worksheet), **The Record Behind the Hunt** (anatomy, מציג את ה-hash), ואז הציד שהלומד כותב בעצמו |

**הפרדה מהשאלות הנבחנות:**
- שרשרת האירוע היא סקריפט מדיסק וירטואלי מותקן דרך wscript.exe, לא Outlook ל-Word ל-PowerShell ‏(q2) ולא קובץ מ-Temp מתחת ל-explorer.exe ‏(la1).
- הזיהוי ב-portal הוא Critical עם Detected, kill process, לא Detected, no action taken (שאלת הביניים של r2, la1). הכלי כן עצר משהו, והלקח הוא שזה נוגע לתהליך אחד.
- severity מול disposition ‏(q1, m1): נלמדים ב-**Anatomy of a Detection** על זיהוי Medium של 7za.exe, ומיושמים ב-**Did It Run?** על חמישה תיקים סגורים.
- שדות ה-m1: מופיעים כנתונים עם תווית בשתי מעבדות האנטומיה, ואף מעבדה לא שואלת אותם. DesiredAccess ו-CallStackModuleNames מוצגים על WerFault.exe מול KilnMonitor.exe, לא על lsass.exe.
- סדר העבודה ‏(o1): הלומד עובר אותו בפועל ב-portal, והמחיר של דילוג נלמד ב-**What the Shortcut Cost**. אף מעבדה לא מבקשת לסדר שלבים.
- זוגות הורה-ילד (q2): ב-**Everyday, Anomaly or Not Enough?** מופיעים MSACCESS אל cscript ו-POWERPNT אל mshta, בלי Outlook אל Word ובלי PowerShell מקודד. המעבדה לא אומרת שהשרשרת מספיקה בלי hash, והלומד מסיק זאת בעצמו.
- תחפושת בשם (la1, שאלה 1): המהלך הראשון של הדו-קרב, על fontsvc.exe ב-ProgramData, לא על UpdateHelper.exe ב-Temp. המעבדה מלמדת שצריך לבדוק מי חתם, בלי ניסוח האפשרות הנכונה.
- מסכת גישה ‏(la1, שאלה 2): ב-**Whose Hand, Whose Memory?** יש 0x1000 על lsass.exe ו-0x1FFFFF על ילד של מתקין, אף פעם לא 2097151 על lsass.exe. הכיוון (מי ניגש למי) נלמד על rundll32.exe מול msedge.exe.
- dbghelp.dll (la1, שאלה 3): הערה ניטרלית על כלי דיווח קריסות שכותב זיכרון של אפליקציה שקרסה. אין שאלה עליו, ומה זה אומר על lsass.exe הלומד מסיק בעצמו.
- disposition ואחים ‏(la1, שאלה 4; q3): AggregateId מוצג כבר באנטומיה. **Three Tickets or One Story?** עוסק במפתח Run, ארכיון והעלאה, לא במשימה מתוזמנת, הורדת PowerShell ו-LSASS, ויש בו גם צביר של ליל טלאים שלא קשור לכלום.
- פסיקה ‏(ac1): **Same Rating, Different Truth** עוסק בארבעה תיקים מהשנה שעברה, עם דרייבר מדפסת דרך rundll32.exe, עם חשבון שירות וכרטיס שינוי אחרים, לא regsvr32.exe, svc-sccm או NexaDeploy. מקרה הכמעט מלמד שכרטיס תקף רק למחשב ולחלון שהוא מציין.
- pivot והיקף (q5): המחשב השלישי מופיע באותו יום, בשם קובץ אחר ועם אותו hash, והמעבדה עוצרת בעובדה: אותו SHA256, אותו קובץ, מחשב שלישי. מה זה אומר על התקרית הלומד מחליט ב-q5.
- חשבון לסיבוב ‏(f1): נלמד על t.vance ב-**A Third Host at 14:20**, לא על r.callahan.
- הכלה (q4): **What Each Response Costs** בודק תגובות ש-q4 לא מציע (השבתת חשבון, sinkhole, חסימת hash, חסימה בחומת האש, Network contain), ואף שורה לא מנצחת לבד.
- הסיגנל המכריע של הבוס (qf1): **Which Way Is Up?** הוא מעבדה משלו. שתי עמודות hash על אותה שורה, כלי אחר (pf.exe) ו-hash אחר, והמעבדה מבקשת לקרוא שורות ולא לכתוב שאילתה או לנקוב בשם העמודה. חריג מכוון: **The Record Behind the Hunt** מציג את רשומת la1, כי qf1 דורש את ה-hash המדויק ומסך הבוס לא מציג אירוע.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Killed Is Not Cured" | כניסה | תחנה 1 |
| Chapter 2: "Not Yet" | אחרי Up the Tree | תחנה 3 |
| Chapter 3: "Back Online" | אחרי The Pivot | תחנה 5 |
| Finale: "Root and Branch" | אחרי The Last Branch | החדר הבא |

סיפור הסרטונים:
- **Intro:** הלילה במעבדת הזיגוג, ספר המתכונים, והזימונית של Mateusz ב-06:52. מנהל המפעל שואל אם זה נגמר. הסרטון מסתיים לפני שפותחים את העץ.
- **Chapter 2:** השיחה של Mateusz עם מנהל המפעל: למה זה עדיין לא נגמר, ולמה צריך לחכות לתשובה מלאה. לא מציג שורש אירוע, קובץ או שם מחשב.
- **Chapter 3:** סוף היום, הצוות עייף, ועדיין נשארת שאלה אחת על מה שהכלי השני עשה. לא מציג עמודות או hash.
- **Finale:** הספר בטוח, Kilnworth משנה את הדרך שבה עובדים מורידים קבצים, וחוזרים לכלל היחיד של Mateusz. מפנה לחדר הבא.
