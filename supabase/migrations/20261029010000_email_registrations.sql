-- Collect early-access email registrations without exposing email addresses.
create table if not exists public.email_registrations (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  created_at timestamptz not null default now(),
  constraint email_registrations_normalized check (email = lower(btrim(email))),
  constraint email_registrations_valid_email check (email ~* '^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$')
);

alter table public.email_registrations enable row level security;
revoke all privileges on table public.email_registrations from anon, authenticated;
grant insert (email) on public.email_registrations to anon, authenticated;
drop policy if exists "Anyone can register an email" on public.email_registrations;
create policy "Anyone can register an email"
  on public.email_registrations
  for insert to anon, authenticated
  with check (email = lower(btrim(email)));
