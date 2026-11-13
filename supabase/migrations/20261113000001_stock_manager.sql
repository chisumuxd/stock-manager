-- ═══════════════════════════════════════════════════════════════════════════
--  GGPLUS Stock Manager on Supabase · 001 · 2026-11-13
--  Same rules as the PHP API (st/api/bootstrap.php) it replaces:
--   · login required for everything (Supabase Auth); anon gets nothing
--   · super = everything · staff need perms.smAll or the shop for sm_<shop>_accounts
--   · viewer / perms.canEdit=false cannot write · admin/password docs are super-only to write
--   · writes ONLY through sm_commit() (merge / mergeFields / delete / optimistic revision checks)
--  Re-runnable (create or replace / if not exists).
-- ═══════════════════════════════════════════════════════════════════════════

create table if not exists public.sm_users (
  user_id      uuid primary key references auth.users(id) on delete cascade,
  username     text not null unique,
  display_name text not null default '',
  role         text not null default 'admin' check (role in ('super','admin','sub','viewer')),
  shops        jsonb not null default '[]'::jsonb,
  perms        jsonb not null default '{}'::jsonb,
  active       boolean not null default true,
  created_at   timestamptz not null default now()
);

create table if not exists public.sm_docs (
  coll       text not null,
  id         text not null,
  data       jsonb not null default '{}'::jsonb,
  rev        bigint not null default 1,
  updated_at timestamptz not null default now(),
  primary key (coll, id)
);
create index if not exists sm_docs_coll_upd on public.sm_docs (coll, updated_at);

alter table public.sm_users enable row level security;
alter table public.sm_docs  enable row level security;
revoke all on public.sm_users, public.sm_docs from anon, public;
revoke insert, update, delete, truncate on public.sm_users, public.sm_docs from authenticated;
grant select on public.sm_users, public.sm_docs to authenticated;

-- ── access decision (mirror of gg_access_denied + gg_state_view) · null = allowed, else the message ──
create or replace function public.sm_access(p_coll text, p_id text, p_write boolean, p_data jsonb default null)
returns text language plpgsql stable security definer set search_path = public as $$
declare me public.sm_users; shops jsonb; all_shops boolean; sm_all boolean; m text; shop text;
begin
  select * into me from public.sm_users where user_id = auth.uid() and active;
  if me.user_id is null then return 'กรุณาเข้าสู่ระบบ'; end if;
  if me.role = 'super' then return null; end if;
  if p_coll in ('app_state','gg_state') and p_id in ('ggSalesPwOverride','sm_authpw') then return 'ไม่มีสิทธิ์'; end if;
  if p_write and (me.role = 'viewer' or coalesce((me.perms->>'canEdit')::boolean, true) = false) then
    return 'บัญชีไม่มีสิทธิ์เพิ่ม แก้ไข หรือลบข้อมูล';
  end if;
  shops     := case when jsonb_typeof(me.shops) = 'array' then me.shops else '[]'::jsonb end;
  sm_all    := coalesce((me.perms->>'smAll')::boolean, false);
  all_shops := shops ? '*' or coalesce((me.perms->>'canViewAllShops')::boolean, false);
  m := substring(p_coll from '^sm_([a-z0-9_-]+)_accounts$');
  if m is not null then
    if sm_all or shops ? '*' then return null; end if;
    if exists (select 1 from jsonb_array_elements_text(shops) s where lower(s) = lower(m)) then return null; end if;
    return 'ไม่มีสิทธิ์เข้าถึงสต็อกร้านนี้';
  end if;
  if p_coll = 'gg_seq' then return 'ไม่มีสิทธิ์จัดการบัญชีผู้ดูแล'; end if;
  if p_coll in ('app_state','gg_state') then
    if p_write and p_id in ('ggAdmins','ggAdmins_bak','ggRoles','ggSalesPwOverride','sm_admins','sm_authpw','sm_authperm') then
      return 'ไม่มีสิทธิ์จัดการบัญชีผู้ดูแล';
    end if;
    return null;
  end if;
  if jsonb_array_length(shops) = 0 and not all_shops and not sm_all then return 'ยังไม่มีสิทธิ์เข้าถึงร้านค้า'; end if;
  if p_coll like 'sm\_%' then return null; end if;
  if p_write and p_data is not null then
    shop := coalesce(p_data->>'shop', p_data->>'shopname', '');
    if shop <> '' and not all_shops
       and not exists (select 1 from jsonb_array_elements_text(shops) s where lower(s) = lower(shop)) then
      return 'ไม่มีสิทธิ์บันทึกร้านค้านี้';
    end if;
  end if;
  return null;
end $$;

create or replace function public.sm_is_super() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.sm_users where user_id = auth.uid() and active and role = 'super')
$$;

drop policy if exists sm_docs_read on public.sm_docs;
create policy sm_docs_read on public.sm_docs for select to authenticated
  using (public.sm_access(coll, id, false) is null);

-- staff list (no secrets in this table) is visible to logged-in users, like the PHP session response
drop policy if exists sm_users_read on public.sm_users;
create policy sm_users_read on public.sm_users for select to authenticated using (true);

-- ── sentinel resolution / merge (mirror of PHP mergeFields(), Firestore merge semantics) ──
-- sentinels from the adapter: {"__ggOp":"deleteField"|"increment"(amount)|"arrayUnion"(items)|"arrayRemove"(items)|"timestamp"}
create or replace function public.sm_resolve(v jsonb) returns jsonb
language plpgsql stable set search_path = public as $$
declare k text; x jsonb; o jsonb; op text;
begin
  if jsonb_typeof(v) = 'object' then
    op := v->>'__ggOp';
    if op = 'timestamp'   then return to_jsonb((extract(epoch from clock_timestamp()) * 1000)::bigint); end if;
    if op = 'increment'   then return to_jsonb(coalesce((v->>'amount')::numeric, 0)); end if;
    if op = 'arrayUnion'  then return coalesce(v->'items', '[]'::jsonb); end if;
    if op = 'arrayRemove' then return '[]'::jsonb; end if;
    o := '{}'::jsonb;
    for k, x in select * from jsonb_each(v) loop
      if jsonb_typeof(x) = 'object' and x->>'__ggOp' = 'deleteField' then continue; end if;
      o := o || jsonb_build_object(k, public.sm_resolve(x));
    end loop;
    return o;
  elsif jsonb_typeof(v) = 'array' then
    return coalesce((select jsonb_agg(public.sm_resolve(e)) from jsonb_array_elements(v) e), '[]'::jsonb);
  end if;
  return v;
end $$;

create or replace function public.sm_merge(old jsonb, patch jsonb) returns jsonb
language plpgsql stable set search_path = public as $$
declare k text; v jsonb; o jsonb; op text; base jsonb; it jsonb;
begin
  o := case when jsonb_typeof(old) = 'object' then old else '{}'::jsonb end;
  for k, v in select * from jsonb_each(coalesce(patch, '{}'::jsonb)) loop
    op := case when jsonb_typeof(v) = 'object' then v->>'__ggOp' end;
    if op = 'deleteField' then
      o := o - k;
    elsif op = 'increment' then
      o := o || jsonb_build_object(k, coalesce(case when jsonb_typeof(o->k) = 'number' then (o->>k)::numeric end, 0)
                                      + coalesce((v->>'amount')::numeric, 0));
    elsif op in ('arrayUnion', 'arrayRemove') then
      base := case when jsonb_typeof(o->k) = 'array' then o->k else '[]'::jsonb end;
      if op = 'arrayUnion' then
        for it in select * from jsonb_array_elements(coalesce(v->'items', '[]'::jsonb)) loop
          if not exists (select 1 from jsonb_array_elements(base) e where e = it) then base := base || jsonb_build_array(it); end if;
        end loop;
      else
        base := coalesce((select jsonb_agg(e) from jsonb_array_elements(base) e
                          where not exists (select 1 from jsonb_array_elements(coalesce(v->'items', '[]'::jsonb)) r where r = e)), '[]'::jsonb);
      end if;
      o := o || jsonb_build_object(k, base);
    elsif jsonb_typeof(v) = 'object' and op is null and jsonb_typeof(o->k) = 'object' then
      o := o || jsonb_build_object(k, public.sm_merge(o->k, v));
    else
      o := o || jsonb_build_object(k, public.sm_resolve(v));
    end if;
  end loop;
  return o;
end $$;

-- ── the only write path · ops = [{collection,id,data,merge?,mergeFields?,type?:'delete'}] · checks = {"coll/id": expectedRev} ──
create or replace function public.sm_commit(p_ops jsonb, p_checks jsonb default '{}'::jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare op jsonb; k text; v jsonb; c text; i text; cur public.sm_docs; err text; nd jsonb; f text; revs jsonb := '{}'::jsonb; nrev bigint;
begin
  if auth.uid() is null then raise exception 'กรุณาเข้าสู่ระบบ' using errcode = '28000'; end if;
  if jsonb_typeof(p_ops) <> 'array' then raise exception 'ops ไม่ถูกต้อง' using errcode = '22023'; end if;
  for k, v in select * from jsonb_each(coalesce(p_checks, '{}'::jsonb)) loop
    c := split_part(k, '/', 1); i := substr(k, length(c) + 2);
    err := public.sm_access(c, i, false);
    if err is not null then raise exception '%', err using errcode = '42501'; end if;
    select * into cur from public.sm_docs where coll = c and id = i for update;
    if coalesce(cur.rev, 0) <> coalesce((v #>> '{}')::bigint, 0) then
      raise exception 'ข้อมูลถูกแก้โดยคนอื่นระหว่างบันทึก' using errcode = 'P0409';   -- not 40001: PostgREST auto-retries serialization failures until timeout
    end if;
  end loop;
  for op in select * from jsonb_array_elements(p_ops) loop
    c := coalesce(op->>'collection', ''); i := coalesce(op->>'id', '');
    if c = '' or i = '' or length(c) > 180 or length(i) > 180 or c ~ '[/\\[:cntrl:]]' or i ~ '[/\\[:cntrl:]]' then
      raise exception 'ชื่อ collection/id ไม่ถูกต้อง' using errcode = '22023';
    end if;
    err := public.sm_access(c, i, true, op->'data');
    if err is not null then raise exception '%', err using errcode = '42501'; end if;
    select * into cur from public.sm_docs where coll = c and id = i for update;
    if op->>'type' = 'delete' then
      delete from public.sm_docs where coll = c and id = i;
      revs := revs || jsonb_build_object(c || '/' || i, coalesce(cur.rev, 0) + 1);
      continue;
    end if;
    if jsonb_typeof(op->'mergeFields') = 'array' then
      if jsonb_array_length(op->'mergeFields') > 40 then raise exception 'mergeFields ไม่ถูกต้อง' using errcode = '22023'; end if;
      nd := case when jsonb_typeof(cur.data) = 'object' then cur.data else '{}'::jsonb end;
      for f in select * from jsonb_array_elements_text(op->'mergeFields') loop
        if f !~ '^[A-Za-z][A-Za-z0-9_]{0,79}$' then raise exception 'mergeFields ไม่ถูกต้อง' using errcode = '22023'; end if;
        if not coalesce(op->'data', '{}'::jsonb) ? f then continue; end if;
        if jsonb_typeof(op->'data'->f) = 'object' and op->'data'->f->>'__ggOp' = 'deleteField' then nd := nd - f;
        else nd := nd || jsonb_build_object(f, public.sm_resolve(op->'data'->f)); end if;
      end loop;
    elsif coalesce((op->>'merge')::boolean, false) then
      nd := public.sm_merge(cur.data, op->'data');
    else
      nd := public.sm_resolve(coalesce(op->'data', '{}'::jsonb));
    end if;
    insert into public.sm_docs as d (coll, id, data, rev, updated_at) values (c, i, nd, 1, now())
      on conflict (coll, id) do update set data = excluded.data, rev = d.rev + 1, updated_at = now()
      returning d.rev into nrev;
    revs := revs || jsonb_build_object(c || '/' || i, nrev);
  end loop;
  return jsonb_build_object('ok', true, 'revisions', revs);
end $$;

revoke all on function public.sm_commit(jsonb, jsonb), public.sm_access(text, text, boolean, jsonb), public.sm_is_super() from anon, public;
grant execute on function public.sm_commit(jsonb, jsonb), public.sm_access(text, text, boolean, jsonb), public.sm_is_super() to authenticated;

-- live updates to the browser (respects the RLS read policy)
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'sm_docs') then
    execute 'alter publication supabase_realtime add table public.sm_docs';
  end if;
end $$;
