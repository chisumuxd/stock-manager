-- ═══════════════════════════════════════════════════════════════════════════
--  003 · fast read policy. Same rules as sm_access(…, false), but the caller's profile is read ONCE per
--  statement (each "(select fn())" is an InitPlan) and every row only does cheap comparisons.
--  (001 called a plpgsql function per row: 200k-row sm_act scans hit the 8 s statement timeout.)
--  sm_access() stays for writes (sm_commit) and for the probe RPC.
-- ═══════════════════════════════════════════════════════════════════════════
create or replace function public.sm_me_super() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.sm_users where user_id = auth.uid() and active and role = 'super') $$;
create or replace function public.sm_me_active() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.sm_users where user_id = auth.uid() and active) $$;
-- every stock shop: perms.smAll or '*' in shops
create or replace function public.sm_me_allstock() returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select coalesce((perms->>'smAll')::boolean, false) or (jsonb_typeof(shops) = 'array' and shops ? '*')
                   from public.sm_users where user_id = auth.uid() and active), false) $$;
-- lower-cased shop list
create or replace function public.sm_me_shops() returns text[] language sql stable security definer set search_path = public as $$
  select coalesce((select array_agg(lower(s)) from public.sm_users u, jsonb_array_elements_text(case when jsonb_typeof(u.shops) = 'array' then u.shops else '[]'::jsonb end) s
                   where u.user_id = auth.uid() and u.active), '{}'::text[]) $$;
-- may see non-stock, non-state collections: has shops, or all shops, or smAll  (PHP: "ยังไม่มีสิทธิ์เข้าถึงร้านค้า")
create or replace function public.sm_me_anyshop() returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select (jsonb_typeof(shops) = 'array' and jsonb_array_length(shops) > 0) or coalesce((perms->>'canViewAllShops')::boolean, false) or coalesce((perms->>'smAll')::boolean, false)
                   from public.sm_users where user_id = auth.uid() and active), false) $$;

revoke all on function public.sm_me_super(), public.sm_me_active(), public.sm_me_allstock(), public.sm_me_shops(), public.sm_me_anyshop() from anon, public;
grant execute on function public.sm_me_super(), public.sm_me_active(), public.sm_me_allstock(), public.sm_me_shops(), public.sm_me_anyshop() to authenticated;

drop policy if exists sm_docs_read on public.sm_docs;
create policy sm_docs_read on public.sm_docs for select to authenticated using (
  (select public.sm_me_super())
  or (
    (select public.sm_me_active())
    and coll <> 'gg_seq'
    and not (coll in ('app_state', 'gg_state') and id in ('ggSalesPwOverride', 'sm_authpw'))
    and case
          when coll like 'sm\_%\_accounts' then
               (select public.sm_me_allstock())
               or lower(substring(coll from '^sm_([a-z0-9_-]+)_accounts$')) = any ((select public.sm_me_shops())::text[])
          when coll in ('app_state', 'gg_state') then true
          when coll like 'sm\_%' then (select public.sm_me_anyshop())
          else (select public.sm_me_anyshop())
        end
  )
);
