# בחינת מוכנות לפרודקשן — HACK THE SOC
### מה נדרש כדי לצאת ל-production בביטחון

- **תאריך:** 22.07.2026
- **בסיס:** אחרי סבב האבטחה, מעבר ה-persistence, סבב הנגישות, שני סבבי QA, וחמישה גלי תיקוני-review.
- **מצב נוכחי:** האתר חי ב-`soc-training-platform-jade.vercel.app`, deploy אחרון **Ready**, build עובר, שערי-תוכן ירוקים.

---

## 0. שורה תחתונה — מוכן לצאת?

**כן — לשימוש בהיקף הנוכחי (בסיס משתמשים קטן), עם 2 פעולות ידניות שלך לפני שמכריזים "מלא".**

הליבה חזקה: אבטחה, RLS, נגישות, ותוכן מאומת. מה שחוסם "מלא" הוא לא באגים — אלא (1) **2 הגדרות ידניות** שרק לך יש גישה אליהן (migration + env), ו-(2) כמה **פערי-הקשחה** שאינם חוסמים אבל כדאיים לפני scale.

---

## 1. 🔴 חוסם — חייב לפני production מלא (פעולות שלך, לא קוד)

| # | מה | למה קריטי | סטטוס |
|---|-----|-----------|-------|
| 1 | **הרצת migration 0008** (XP סמכותי) ב-Supabase | בלעדיו `profiles.xp` עדיין ניתן לכתיבה מה-devtools (הזרקת ניקוד). הקוד מוכן, ה-SQL סופק | ⏳ ממתין לך |
| 2 | **הגדרת `SUPABASE_SERVICE_ROLE_KEY` ב-Vercel** | בלעדיו: audit-log נכתב רק ל-stderr (לא ל-DB), ו-XP סמכותי לא נאכף. עם: תיעוד מלא | ⏳ ממתין לך |
| 3 | **הגדרת `UPSTASH_REDIS_REST_URL/TOKEN` ב-Vercel** | בלעדיו: rate-limit בזיכרון (מתאפס בין serverless instances) → מסלולי ה-LLM חשופים לניצול-תקציב. עם: rate-limit עמיד | ⏳ ממתין לך |

> **בלי אלה האתר עובד** (fallback בטוח בכל מקום) — אבל שלוש ההקשחות האלה הן ההבדל בין "עובד" ל"מוקשח לפרודקשן".

---

## 2. 🟡 מומלץ לפני scale (לא חוסם היום)

| # | מה | הערה |
|---|-----|------|
| 4 | **תלויות שיוריות** — `postcss`/`sharp` מוטמעים ב-Next + שרשרת eslint (dev-only) | דורש שדרוג ל-Next 16 + eslint 9 (שרשרת major). סיכון-אמת נמוך (postcss build-time, sharp ש-Vercel מטפל, eslint dev בלבד) |
| 5 | **CSP — הסרת `unsafe-inline` מ-script-src** | דורש מעבר ל-CSP מבוסס-nonce ב-middleware. כרגע ה-CSP אוכף את שאר ההנחיות; XSS מנוטרל גם במקור |
| 6 | **חוב read-timing ב-persistence** | רכיבים קוראים את ה-facade לפני שה-hydrate של ה-remote backend הסתיים → במכשיר חדש ערכים עלולים להופיע ריקים עד reload. פתרון: אות "hydrated" מ-`ProgressProvider` |
| 7 | **מבדק חדירות אקטיבי + סבב קורא-מסך** | לפני הכרזת עמידה רגולטורית (אבטחה/נגישות) — בדיקה חיצונית |

---

## 3. 🟢 חוב מתועד / החלטות מוצר (לא חוסם)

- **שדות `cs.*/siem.*`** — ✅ **תוקן** (סבב log-generator + אימות שלי): `cs.*`→`crowdstrike.*` (הקונבנציה הפנימית), `siem.*`→שדות SecurityAlert/ECS אמיתיים או `ExtendedProperties.*` (bag לגיטימי של Sentinel), ושדות אנליטיקה-נגזרת שחיישן לא פולט **הוסרו**. שערים ירוקים, baseline ירד 3840→3714.
- **יחס תג-MITRE ברקע** — החלטת עיצוב פדגוגי (לא שינוי מכני).
- **איחוד שתי מערכות ה-Learning Path** — הסרנו את ההתקדמות המזויפת; המיזוג המלא (עם lesson-progress אמיתי בצד-שרת) הוא פרויקט-פיצ'ר.
- **פיצ'רי engagement** — leaderboard, חגיגת badge בזמן-אמת, streak-push (opt-in email). כולם דורשים תשתית חדשה.
- **Low/design** — טקסטים 9-10px, double-password אחרי signup (מכוון), FlagPlayer ניסיונות ללא הגבלה.

---

## 4. ✅ מה שכבר מוכן לפרודקשן (נבדק ואומת)

- **אבטחה**: RLS מהודק (0004/0005/0007), apiGuard fail-closed עם JWT, אין סודות מוקשחים, CSP אוכף, audit-trail, security headers מלאים.
- **נגישות**: תוויות טופס, skip-link, ניגודיות AA, הצהרת נגישות + מייל קשר, כותרות דף.
- **דיוק תוכן**: שערי-CI ירוקים (audit 0, validate:scenarios 0, validate:logs pass), 317+699 אירועים מאומתים.
- **יציבות**: 2 סבבי QA (0 רגרסיות), tsc 0, production build 0, deploy Ready.
- **אמינות נתונים**: persistence מנותב ל-DB (תרחישים/חדרים/dashboard/cleared/streak), שם-תעודה דינמי, rank מאוחד.

---

## 5. Checklist מהיר לפני "Go"

- [ ] הרצת migration 0008 (SQL סופק) + אימות: `select xp,xp_offset from profiles` ללא שינוי; הזרקת XP נחסמת
- [ ] `SUPABASE_SERVICE_ROLE_KEY` ב-Vercel env
- [ ] `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` ב-Vercel env
- [ ] אימות ש-Vercel deploy עבר אחרי כל push (✅ אושר ל-`8c6f343`)
- [ ] מילוי פרטי גורם נגישות בעמוד `/accessibility` (מייל כבר מולא)
- [ ] (מומלץ) סבב קורא-מסך + מבדק חדירות לפני הכרזת עמידה רגולטורית

---
*יעודכן עם סיום סבב ה-log-generator (cs/siem) ואחרי ה-build+push הסופי.*
