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

## The tenant config (one place for everything)

Each organization has ONE tenant config, and every screen reads from it. No component writes a product name, logo, colour, font or link of its own.

| Part | Stored in | Read with |
| --- | --- | --- |
| Product name, logo, support email, sender | `organizations.branding` | `useBrand()` (client), `getRequestBrand()` / `brandForOrg()` (server) |
| Domain | `organizations.custom_domain` | `brand.origin` |
| Theme: colours, font, corners, button style | `branding.theme` | CSS variables (below) |
| Links: privacy, terms, help | `branding.links` | `brand.links` |
| Plan features | `branding.features` | `useFeatures()`, `requireFeature()` |

Code: `src/lib/brand/brand.ts` (the type), `theme.ts`, `features.ts`, `sanitize.ts` (what the super-admin may save). All of it is edited on the organization's page in Super Admin: the Branding card (white label, theme with presets and a live preview, links) and the Features card.

### Theme tokens

Every visual decision is a CSS variable, declared in `globals.css :root` and `theme.ts DEFAULT_TOKENS`. A test keeps the two lists identical.

| Token | Tailwind | Theme key |
| --- | --- | --- |
| `--cyber-50` … `--cyber-900` | `cyber-*`, `shadow-glow`, focus outline | `accent` (step 400 = that colour) |
| `--bg`, `--bg-elevated`, `--bg-panel`, `--bg-hover`, `--border`, `--border-strong` | `bg-bg*`, `border-border*` | `background` (must be dark) |
| `--on-accent` | `text-on-accent` | computed from the accent for contrast |
| `--font-sans` | `font-sans` | `font`: inter, heebo, rubik, assistant |
| `--radius-sm` … `--radius-2xl` | `rounded-sm` … `rounded-2xl` | `radius`: sharp, default, round |
| `--glow-alpha` | `shadow-glow` strength | `buttons`: glow, flat |

Rules for new code: use these classes only. No `cyan-*`, no `bg-[#0d1520]`-style surface colours, no `#22d3ee`. Canvas, PDF and email code read colours with `tokenHex` / `tokenRgb` / `tokenRgba(theme, token)`.

What stays fixed on purpose: the semantic colours (`neon-*`, `severity-*`), because red means malicious and green means benign for every customer; third-party brand colours (the LinkedIn share button); the per-company colours of the simulated companies; the multicolour illustration palette of generic cover art.

The theme also reaches:
- **Slide decks:** `rebrandDocument` sets the deck's own palette variables (`--cyan`, `--bg`, …) and replaces every lockup, including the small mark in each slide's corner.
- **Certificates** (rank PNG and scenario PDF): frame, glow and corner ticks.
- **Emails:** button colour (the accent's darker 600 step, readable on white) and the header band.
- **Lesson cover art:** covers drawn in the platform cyan take the accent.

Where the theme applies:
- **On the org's own domain:** rendered on the server, so there is no flash of the default look.
- **Inside its environment on the platform host:** applied in the app only, removed when the user leaves the app.
- **Everywhere else:** never. The platform keeps its look.

### Plan features

`features.ts` lists the parts of the platform a plan can include (Learning Rooms, Live SOC + EDR, Learning Path, Scenarios, Quizzes, Achievements, College Materials, Team Training). Missing = on, so existing organizations keep everything. A feature that is off:
- disappears from the sidebar;
- its pages redirect to `/progress?reason=feature` on the server (each route's `layout.tsx` calls `requireFeature`), with a notice;
- Team Training also refuses to create or start an exercise in the API.

Features apply to every organization, white label or not. The super-admin is never blocked, so they can look around any environment.

## Local testing

`*.localhost` is not a platform host. Put `NEXT_PUBLIC_WL_BASE_DOMAIN=wl.localhost` in `.env.development.local`, turn white label on for a staging org, run the dev server and open `http://<slug>.wl.localhost:3810`. An own domain can be tested the same way, e.g. `wl-demo.localhost`.

## Limits

- **Lesson video files** still contain the outro. The player stops before it, but a downloaded file still ends with the platform logo.
- **PDF certificate text** uses Helvetica, so a Hebrew product name won't print. Keep product names in Latin script, or add a Hebrew font to the PDF.
- **Light mode:** not supported yet. The theme background must be dark; the save refuses a light one.
- **Brand changes** reach every server instance within one minute (per-instance cache).
