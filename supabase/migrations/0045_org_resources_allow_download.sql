-- College Materials: downloads are OFF by default. The org admin opts a specific
-- resource into being downloadable; until then students can only VIEW it in-app.
alter table public.org_resources
  add column if not exists allow_download boolean not null default false;
