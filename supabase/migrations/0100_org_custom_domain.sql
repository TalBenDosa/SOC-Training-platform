-- 0100: white label, the organization's own domain (Tal, 2026-10-19).
--
-- A white-label customer runs the platform on its own host name (e.g. soc.college.ac.il) under
-- its own name and logo, end to end. The host a request arrives on picks the organization's
-- brand; emailed links are built from this column (never from the request's Host header).
-- The rest of the brand (white_label flag, product name, logo, support email, sender) lives in
-- organizations.branding (jsonb, since 0010). NULL = no own domain (every existing org).
-- Written only by the super-admin API (service role); readable by the org's members under the
-- existing RLS. Stored lower-case, without scheme, port or path.
--
-- Verify: select column_name, data_type, is_nullable from information_schema.columns
--          where table_schema = 'public' and table_name = 'organizations' and column_name = 'custom_domain';
--         -> text, YES
--         select indexname from pg_indexes where indexname = 'organizations_custom_domain_key';
--         -> 1 row

alter table public.organizations
  add column if not exists custom_domain text
  constraint organizations_custom_domain_format check (
    custom_domain is null
    or (custom_domain = lower(custom_domain)
        and length(custom_domain) between 4 and 253
        and custom_domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
  );

create unique index if not exists organizations_custom_domain_key
  on public.organizations (custom_domain) where custom_domain is not null;

comment on column public.organizations.custom_domain is
  'White label: the host name this organization''s members use (lower-case, no scheme/port/path). NULL = none.';
