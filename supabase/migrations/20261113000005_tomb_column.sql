-- ═══════════════════════════════════════════════════════════════════════════
--  005 · stored "tomb" flag so counts never de-TOAST account documents (~8 KB each, 170k rows)
--  sm_counts() hit the 8 s timeout reading data->>'x' for every account doc.
-- ═══════════════════════════════════════════════════════════════════════════
alter table public.sm_docs add column if not exists tomb boolean generated always as (coalesce(data->>'x', '') = 'true') stored;

drop function if exists public.sm_counts();
create or replace function public.sm_counts(p_coll text default null) returns table (coll text, docs bigint, live bigint)
language sql stable security definer set search_path = public as $$
  select d.coll, count(*) as docs, count(*) filter (where not d.tomb) as live
  from public.sm_docs d
  where d.coll like 'sm\_%\_accounts' and d.coll ~ '^sm_[a-z0-9_-]+_accounts$' and (p_coll is null or d.coll = p_coll)
  group by d.coll
  having public.sm_access(d.coll, '', false) is null
$$;
revoke all on function public.sm_counts(text) from anon, public;
grant execute on function public.sm_counts(text) to authenticated;

-- index-only counting per shop (needs a VACUUM after big rewrites so the visibility map is set)
create index if not exists sm_docs_acct_tomb on public.sm_docs (coll, tomb) where coll like 'sm\_%\_accounts';
