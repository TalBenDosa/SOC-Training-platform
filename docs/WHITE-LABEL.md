# White label

A white-label organization runs the platform under its own name, logo and domain, end to end. Its learners and admins never see HACK THE SOC: not on sign-in, in tab titles, in the sidebar, in emails, on certificates, in the slide decks or at the end of the lesson videos.

## What the platform does

| Surface | White-label behaviour | Code |
| --- | --- | --- |
| Which brand | Picked by the request's host name: `<slug>.<NEXT_PUBLIC_WL_BASE_DOMAIN>`, or the org's own domain (`organizations.custom_domain`, migration 0100). Platform hosts (hackthesoc.app, *.vercel.app, localhost) never look one up. | `src/lib/brand/server.ts` |
| Front door | `/` on the org's domain goes straight to sign-in (no HACK THE SOC landing page). | `src/app/page.tsx` |
| Logo and name | Sidebar, sign-in and every other `<Logo>` show the org's logo and product name. | `src/components/Logo.tsx` |
| Tab titles, favicon | `<page> // <product name>`; the uploaded logo is the favicon; pages are `noindex`. | `src/lib/brand/metadata.ts`, `src/app/layout.tsx` |
| Emails | Invites, password reset, admin sign-in, learning plans, reminders and report replies carry the org's name, logo and accent colour, and their links use the org's domain (from the database, never the request's Host). | `emailContextForOrg`, `src/lib/email/templates.ts` |
| Email sender | `branding.email_from` if set (that domain must be verified in Resend), else the product name with the platform's address. | `senderFor` |
| Certificates | Rank certificates and the scenario PDF show the org's logo, name and domain. | `src/lib/certificate/*`, `CompletionModal.tsx` |
| Slide decks | The deck's logo lockup and name are swapped for the org's when the deck opens. | `src/lib/brand/rebrandDocument.ts` |
| Lesson videos | Playback stops before the 4-second HACK THE SOC outro burned into the files. | `src/components/lessons/LessonVideo.tsx` |
| Messages to admins | "Contact HACK THE SOC" becomes the org's support email (or "your platform administrator"). | `contactLine` |
| Privacy / accessibility pages | Product name, and the org's support email as the contact. | `src/app/privacy`, `src/app/accessibility` |

## One-time setup (once for all customers)

Every white-label customer gets an automatic address, `<org slug>.<base domain>` (e.g. `northwind.soc-academy.app`). Set it up once:

1. Buy a neutral domain that does not say HACK THE SOC (e.g. `soc-academy.app`).
2. Point its nameservers at Vercel (Vercel shows the two `ns*.vercel-dns.com` names). A wildcard needs Vercel's nameservers.
3. Vercel → Project → Settings → Domains → add `*.soc-academy.app`.
4. Vercel → Settings → Environment Variables → add `NEXT_PUBLIC_WL_BASE_DOMAIN` = `soc-academy.app` (Production), then redeploy.

## Onboarding a white-label customer (no DNS, no Vercel)

1. **Super Admin → the organization → Branding**: tick *White label*, then fill in:
   - product name
   - logo: PNG, JPEG or WebP, up to 150 KB, shown on a dark background
   - support email

   Save.
2. The screen shows the address, e.g. `https://northwind.soc-academy.app`. It works immediately. Send it to the customer, and every email link already points there.

### Optional: the customer's own domain

If the customer wants `soc.college.ac.il`:
- type that domain in *Own domain*
- add the domain in Vercel (Settings → Domains)
- have the customer add the CNAME that Vercel shows

Nothing else is needed. Password reset and invite links don't go through the Supabase redirect list.

### Optional: email from the customer's domain

This needs a paid Resend plan (the free plan allows one domain):
- verify the domain in Resend
- have the customer add its DNS records
- set *Email sender*, e.g. `College SOC <noreply@college.ac.il>`

Until then, mail comes from the product name at `noreply@hackthesoc.app`.

## Themes (per-customer colours)

The app's colours are CSS variables, defined in `src/lib/brand/theme.ts` and `globals.css :root`:
- `--cyber-50` to `--cyber-900`: the accent
- `--bg*`: the surfaces
- `--border*`: the lines

Tailwind's `cyber-*`, `bg-bg*` and `border-border*` classes read these variables. A white-label org can store a theme in `organizations.branding.theme`, for example `{"accent":"#3b9ae1","background":"#0c1626"}`:

| Key | What it changes |
| --- | --- |
| `accent` | Generates the whole accent scale. Step 400 is exactly that colour. |
| `background` | Derives the panels, hover states and borders. |

Where the theme applies:
- **On the org's own domain:** rendered on the server, so there is no flash of the default palette.
- **Inside its environment on the platform host:** applied in the app only, and removed when the user leaves the app.
- **Everywhere else:** never. The platform keeps its palette.

There is no Super Admin field for it yet. Until then, set it in the database: the server validates `#rrggbb`. A test guarantees the default tokens in the code and in the CSS stay identical.

Not themed yet: about 14 hard-coded `#22d3ee` uses (charts, a few glows) and the semantic colours (`neon-*`, `severity-*`), which carry meaning (red = malicious).

## Local testing

`*.localhost` is not a platform host. Put `NEXT_PUBLIC_WL_BASE_DOMAIN=wl.localhost` in `.env.development.local`, turn white label on for a staging org, run the dev server and open `http://<slug>.wl.localhost:3810`. An own domain can be tested the same way, e.g. `wl-demo.localhost`.

## Limits

- **Lesson video files** still contain the outro. The player stops before it, but a downloaded file still ends with the platform logo.
- **PDF certificate text** uses Helvetica, so a Hebrew product name won't print. Keep product names in Latin script, or add a Hebrew font to the PDF.
- **Accent colour** applies to the logo, emails and buttons in emails. The app's cyan theme stays the same.
- **Brand changes** reach every server instance within one minute (per-instance cache).
