-- ═══════════════════════════════════════════════════════════════════════════
--  GGPLUS Stock Manager on Supabase · 002 · RPCs used by api/gg-supabase.js + filter indexes
-- ═══════════════════════════════════════════════════════════════════════════

-- account document counts per shop the caller may see (replaces the counts part of stock-manager-inventory.php)
create or replace function public.sm_counts() returns table (coll text, docs bigint, live bigint)
language sql stable security definer set search_path = public as $$
  select d.coll, count(*) as docs, count(*) filter (where coalesce(d.data->>'x', '') <> 'true') as live
  from public.sm_docs d
  where d.coll ~ '^sm_[a-z0-9_-]+_accounts$'
  group by d.coll
  having public.sm_access(d.coll, '', false) is null
$$;

-- staff management (replaces usersAdminWrite in index.php) · super only
-- p = {op:'create'|'update'|'delete'|'setDisplayName', username, display_name?, password?, role?, shops?, perms?, active?}
create or replace function public.sm_admin_user(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, auth, extensions as $$
declare
  op    text := coalesce(p->>'op', '');
  uname text := lower(trim(coalesce(p->>'username', '')));
  dn    text := coalesce(nullif(trim(p->>'display_name'), ''), lower(trim(coalesce(p->>'username', ''))));
  pw    text := coalesce(p->>'password', '');
  r     text := coalesce(nullif(p->>'role', ''), 'admin');
  em    text;
  uid   uuid;
  me    uuid := auth.uid();
begin
  if not public.sm_is_super() then raise exception 'เฉพาะแอดมินสูงสุด' using errcode = '42501'; end if;
  if uname = '' then raise exception 'ไม่มีชื่อผู้ใช้' using errcode = '22023'; end if;
  em := regexp_replace(uname, '[^a-z0-9._-]+', '_', 'g') || '@staff.bearplus.biz';
  select user_id into uid from public.sm_users where lower(username) = uname;

  if op = 'setDisplayName' then
    if uid is null then raise exception 'ไม่พบบัญชี %', uname using errcode = '22023'; end if;
    update public.sm_users set display_name = dn where user_id = uid;
    return jsonb_build_object('ok', true, 'display_name', dn);
  end if;

  if op = 'delete' then
    if uid is null then return jsonb_build_object('ok', true, 'deleted', false); end if;
    if uid = me then raise exception 'ลบบัญชีตัวเองไม่ได้' using errcode = '42501'; end if;
    if exists (select 1 from public.sm_users where user_id = uid and role = 'super') then raise exception 'ลบแอดมินสูงสุดไม่ได้' using errcode = '42501'; end if;
    delete from auth.users where id = uid;            -- cascades to public.sm_users
    return jsonb_build_object('ok', true, 'deleted', true);
  end if;

  if op not in ('create', 'update') then raise exception 'op ไม่ถูกต้อง' using errcode = '22023'; end if;
  if uname !~ '^[a-z0-9_.-]{3,100}$' then raise exception 'ชื่อผู้ใช้ต้องเป็นภาษาอังกฤษ 3–100 ตัว' using errcode = '22023'; end if;
  if r not in ('admin', 'viewer', 'sub') then raise exception 'ยศไม่ถูกต้อง' using errcode = '22023'; end if;
  if pw <> '' and length(pw) < 8 then raise exception 'รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร' using errcode = '22023'; end if;

  if uid is null then
    if op = 'update' then raise exception 'ไม่พบบัญชี %', uname using errcode = '22023'; end if;
    if pw = '' then raise exception 'บัญชีใหม่ต้องตั้งรหัสผ่าน' using errcode = '22023'; end if;
    if exists (select 1 from auth.users where email = em) then raise exception 'อีเมลภายในซ้ำ: %', em using errcode = '23505'; end if;
    uid := gen_random_uuid();
    insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
                            raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
                            confirmation_token, recovery_token, email_change_token_new, email_change, email_change_token_current, reauthentication_token)
    values ('00000000-0000-0000-0000-000000000000', uid, 'authenticated', 'authenticated', em, crypt(pw, gen_salt('bf', 10)), now(),
            '{"provider":"email","providers":["email"]}'::jsonb, jsonb_build_object('username', uname), now(), now(),
            '', '', '', '', '', '');
    insert into auth.identities (id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
    values (gen_random_uuid(), uid, uid::text, jsonb_build_object('sub', uid::text, 'email', em, 'email_verified', true), 'email', now(), now(), now());
    insert into public.sm_users (user_id, username, display_name, role, shops, perms, active)
    values (uid, uname, dn, r, coalesce(p->'shops', '[]'::jsonb), coalesce(p->'perms', '{}'::jsonb), coalesce((p->>'active')::boolean, true));
    return jsonb_build_object('ok', true, 'created', true, 'username', uname, 'display_name', dn);
  end if;

  if exists (select 1 from public.sm_users where user_id = uid and role = 'super') then raise exception 'แก้แอดมินสูงสุดจากหน้านี้ไม่ได้' using errcode = '42501'; end if;
  update public.sm_users set display_name = dn, role = r,
         shops = coalesce(p->'shops', shops), perms = coalesce(p->'perms', perms), active = coalesce((p->>'active')::boolean, active)
   where user_id = uid;
  if pw <> '' then update auth.users set encrypted_password = crypt(pw, gen_salt('bf', 10)), updated_at = now() where id = uid; end if;
  return jsonb_build_object('ok', true, 'updated', true, 'username', uname, 'display_name', dn);
end $$;

revoke all on function public.sm_counts(), public.sm_admin_user(jsonb) from anon, public;
grant execute on function public.sm_counts(), public.sm_admin_user(jsonb) to authenticated;

-- indexes for the filters the page uses (sm_act is ~200k rows)
create index if not exists sm_act_acc  on public.sm_docs ((data->>'acc'))                 where coll = 'sm_act';
create index if not exists sm_act_day  on public.sm_docs ((data->>'day'))                 where coll = 'sm_act';
create index if not exists sm_act_by   on public.sm_docs ((data->>'by'))                  where coll = 'sm_act';
create index if not exists sm_act_svct on public.sm_docs ((data->>'svc'), (data->>'t'))   where coll = 'sm_act';
create index if not exists sm_act_cd   on public.sm_docs ((data->>'cd'))                  where coll = 'sm_act';
create index if not exists sm_actsum_m on public.sm_docs ((data->>'m'))                   where coll = 'sm_act_sum';
