# White label

A white-label organization runs the platform under its own name, logo and domain, end to end. Its learners and admins never see HACK THE SOC: not on sign-in, in tab titles, in the sidebar, in emails, on certificates, in the slide decks or at the end of the lesson videos.

## What the platform does

| Surface | White-label behaviour | Code |
| --- | --- | --- |
| Which brand | Picked by the request's host name (`organizations.custom_domain`, migration 0100). Platform hosts (hackthesoc.app, *.vercel.app, localhost) never look one up. | `src/lib/brand/server.ts` |
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

## Onboarding a white-label customer

1. **Super Admin → the organization → Branding**: tick *White label*, then fill in:
   - product name
   - own domain (e.g. `soc.college.ac.il`)
   - support email
   - logo: PNG, JPEG or WebP, up to 150 KB, shown on a dark background
   - optionally, an email sender

   Save.
2. **Vercel**: Project → Settings → Domains → add the domain.
3. **Customer's DNS**: a CNAME from the domain to the target Vercel shows (usually `cname.vercel-dns.com`). Vercel issues the TLS certificate once it resolves.
4. **Supabase** (prod): Authentication → URL Configuration → add `https://<domain>/**` to Redirect URLs.
5. **Email from their own domain** (optional): this needs a paid Resend plan, since the free plan allows one domain. Verify the domain in Resend, have the customer add its DNS records, then set *Email sender* to e.g. `College SOC <noreply@college.ac.il>`. Until then, mail comes from the product name at `noreply@hackthesoc.app`.
6. **Check**:
   - open `https://<domain>`: it should show the sign-in page with the org's logo and name
   - sign in, open a room, a deck and a lesson video
   - send yourself a password reset

## Local testing

`*.localhost` is not a platform host, so it stands in for a customer domain. Set the org's custom domain to e.g. `wl-demo.localhost` (staging only), run the dev server and open `http://wl-demo.localhost:3810`.

## Limits

- **Lesson video files** still contain the outro. The player stops before it, but a downloaded file still ends with the platform logo.
- **PDF certificate text** uses Helvetica, so a Hebrew product name won't print. Keep product names in Latin script, or add a Hebrew font to the PDF.
- **Accent colour** applies to the logo, emails and buttons in emails. The app's cyan theme stays the same.
- **Brand changes** reach every server instance within one minute (per-instance cache).
