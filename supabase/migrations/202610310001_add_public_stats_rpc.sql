create or replace function public.get_public_stats()
returns jsonb
language sql
stable
security definer
set search_path = public
as $$
  select jsonb_build_object(
    'checks_this_month', (select count(*) from public.checks where created_at >= date_trunc('month', now())),
    'scam_reports', (select count(*) from public.scam_reports),
    'published_reports', (select count(*) from public.scam_reports where status = 'published'),
    'accuracy_rate', null
  );
$$;
revoke all on function public.get_public_stats() from public;
grant execute on function public.get_public_stats() to anon, authenticated;
