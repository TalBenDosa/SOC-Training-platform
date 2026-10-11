-- 0091_block_disposable_email.sql
-- Client feedback: a course must be able to reach every registrant, so disposable /
-- anonymous-alias mailboxes (e.g. passinbox.com) are refused. The signup page does an
-- instant client-side check for the friendly message; THIS is the non-bypassable backstop
-- (a direct supabase.auth.signUp call can't get around it).
--
-- Kept deliberately simple and defensive so it can NEVER block a legitimate signup:
--  * only an exact apex-domain match in the curated list raises;
--  * a null / malformed email is passed through (other validation handles it);
--  * SECURITY DEFINER + fixed search_path.
-- Mirror of DISPOSABLE_DOMAINS in src/lib/auth/emailBlocklist.ts — keep in sync.

create or replace function public.disposable_email_domains()
returns text[] language sql immutable set search_path = public as $$
  select array[
    'mailinator.com','guerrillamail.com','guerrillamail.net','sharklasers.com',
    '10minutemail.com','10minutemail.net','temp-mail.org','tempmail.com','tempmailo.com',
    'tempmail.net','tmpmail.org','throwawaymail.com','getnada.com','nada.email',
    'dispostable.com','trashmail.com','trashmail.de','maildrop.cc','mohmal.com',
    'yopmail.com','yopmail.net','fakeinbox.com','mailnesia.com','mintemail.com',
    'spamgourmet.com','mailcatch.com','emailondeck.com','moakt.com','tempr.email',
    'mailtemp.net','burnermail.io','33mail.com','spam4.me','grr.la','inboxbear.com',
    'tempinbox.com','mail-temp.com','disposablemail.com','harakirimail.com',
    'passinbox.com','passmail.com','passmail.net',
    'simplelogin.com','simplelogin.io','slmail.me','aleeas.com',
    'anonaddy.com','anonaddy.me','addy.io',
    'duck.com','relay.firefox.com','mozmail.com'
  ]
$$;

create or replace function public.reject_disposable_email()
returns trigger language plpgsql security definer set search_path = public as $$
declare v_domain text;
begin
  v_domain := lower(split_part(coalesce(new.email, ''), '@', 2));
  if v_domain <> '' and v_domain = any (public.disposable_email_domains()) then
    raise exception 'disposable_email: % is a temporary or anonymous-forwarding address', v_domain
      using errcode = 'check_violation';
  end if;
  return new;
end $$;

drop trigger if exists reject_disposable_email on auth.users;
create trigger reject_disposable_email
  before insert on auth.users
  for each row execute function public.reject_disposable_email();

revoke execute on function public.disposable_email_domains() from public, anon, authenticated;
