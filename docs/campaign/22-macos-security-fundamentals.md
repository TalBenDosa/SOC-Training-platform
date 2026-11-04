# תסריט חדר 22: macOS Security Fundamentals

**שם המבצע:** Operation Orchard
**רמה:** מתחילים
**העולם:** Corva Studios (סטודיו עיצוב בדוי): ‏180 מעצבים, ‏180 מחשבי MacBook, וצוות אנליסטים שהוכשר על Windows.
**המנטורית:** Mei Tran, מהנדסת אבטחת macOS.

## סיפור הרקע
מתחת לממשק, macOS היא מערכת Unix. יש לה שערים משלה:
- תגי quarantine.
- Gatekeeper.
- חתימות קוד.
- הסכמת פרטיות (TCC).
- launchd.

Mei מאבטחת את הצי. היא תיתן לך טרמינל ואת אותן שאלות שהיא שואלת על כל Mac חשוד: מאיפה התוכנה נכנסה, מי ערב לה, ואיפה היא מתחבאת כדי להישאר.

## העולם התלת-ממדי: Orchard
- ליבת Unix בשם XNU.
- שתי דלתות כניסה: דיסק DMG, וארגז PKG שקו הסקריפט שלו יוצא אל שרת.
- קשת GATEKEEPER שחבילות עם תג quarantine עוברות דרכה, ולידה שלוש חותמות: DEV ID זהובה, ‏AD-HOC אפורה ו-REVOKED אדומה.
- דיאלוג סיסמה מזויף ליד כספת KEYCHAIN שדולפת.
- שורת מתגי TCC, שאחד מהם (ACCESS) אדום.
- עץ launchd עם פירות agents ו-daemons, ואחד מהם אדום.

## סדר המשימות (שונה כדי שכל תחנה תהיה רציפה)
r1 | r2, q1 | r3, r4, q2 | r5, q3, la2, r6 | r7, la1, f1 | r8, q4, ac1, q5, m1, o1

ה-log analysis של TCC ‏(la1) והדגל שלו עברו אל אחרי r7, שבו TCC נלמד. ה-la2 של osascript עבר אל r5.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Unix Underneath | r1 | **Translate to macOS**: ‏Registry מול plist, ‏Run key מול LaunchAgent, ‏SCM מול launchd, ‏MOTW מול quarantine |
| 2 | Two Doors In | r2, q1 | **Mount One, Unpack the Other**: ‏hdiutil attach, ‏pkgutil --expand ו-cat postinstall |
| 3 | Who Vouches for It | r3, r4, q2 | **Who Vouches for It?**: ‏xattr -l, ‏spctl -a -vvv ו-codesign -dvv (מאושרת, לא עברה notarization, ‏ad-hoc) |
| 4 | Scripts and Secrets | r5, q3, la2, r6 | **Admin Tool or Abuse?**: חמש פקודות osascript. **Trace the Keychain Dump**: ‏log show ו-ps עד ל-renderd |
| 5 | The Privacy Gate | r7, la1, f1 | **Read the Consent Database**: שורות TCC ממסד המשתמש וממסד המערכת (auth_value ו-auth_reason) |
| 6 (בוס) | Staying Power | r8, q4, ac1, q5, m1, o1 | **What Starts on Its Own?**: שלוש תיקיות launchd, ‏plutil -p ו-KeepAlive |

**הפרדה מהשאלות הנבחנות:**
- הקונסולות לא שואלות למה PKG מסוכן יותר (q1), ולא בודקות את החתימה של osascript (q2).
- המיון לא כולל דיאלוג סיסמה עם hidden answer (q3, la2).
- דף ה-TCC קורא שורות, ולא כתיבה של root עם sqlite3 (la1, f1).
- קונסולת launchd מוצאת daemon אחד וקוראת את ה-plist שלו. היא לא משווה בין agents ל-daemons (q4, q5), ולא עוסקת ב-Notion (ac1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Unix With Its Own Gates" | כניסה | תחנה 1 |
| Chapter 2: "Who Vouches for It" | אחרי Two Doors In | תחנה 3 |
| Chapter 3: "The Password Is the Key" | אחרי Scripts and Secrets | תחנה 5 |
| Finale: "KeepAlive" | אחרי הבוס | החדר הבא: Windows Event Logs |
