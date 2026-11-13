-- ═══════════════════════════════════════════════════════════════════════════
--  004 · sm_list / sm_count: filtered collection reads that can use the expression indexes.
--  Under RLS, filters on data->>'field' cannot use indexes (->> is not leakproof), so a 200k-row sm_act
--  lookup scanned the whole collection. Access depends only on the collection (plus 2 hidden app_state ids),
--  so these functions check sm_access(coll) once and then query directly.
--  filters: [{"field":"day","op":">=","value":"2026-11-10"}, …]  ops: == != in >= > <= < array-contains
-- ═══════════════════════════════════════════════════════════════════════════
create or replace function public.sm_where(p_filters jsonb) returns text
language plpgsql immutable set search_path = public as $$
declare f jsonb; fld text; op text; v jsonb; col text; w text := '';
begin
  for f in select * from jsonb_array_elements(coalesce(p_filters, '[]'::jsonb)) loop
    fld := f->>'field'; op := f->>'op'; v := f->'value';
    if fld = '__name__' then col := 'id';
    elsif fld ~ '^[A-Za-z0-9_]{1,80}$' then col := format('(data->>%L)', fld);
    else raise exception 'field ไม่ถูกต้อง' using errcode = '22023'; end if;
    w := w || ' and ' || case op
      when '==' then case when v is null or jsonb_typeof(v) = 'null' then col || ' is null' else col || ' = ' || quote_literal(v #>> '{}') end
      when '!=' then col || ' is distinct from ' || quote_literal(v #>> '{}')
      when 'in' then col || ' = any (' || quote_literal(coalesce((select array_agg(e #>> '{}') from jsonb_array_elements(v) e), '{}'::text[])) || '::text[])'
      when '>=' then col || ' >= ' || quote_literal(v #>> '{}')
      when '>'  then col || ' > '  || quote_literal(v #>> '{}')
      when '<=' then col || ' <= ' || quote_literal(v #>> '{}')
      when '<'  then col || ' < '  || quote_literal(v #>> '{}')
      when 'array-contains' then format('(data->%L) @> %L::jsonb', fld, jsonb_build_array(v))
      else null end;
    if w is null then raise exception 'op ไม่รองรับ' using errcode = '22023'; end if;
  end loop;
  return w;
end $$;

create or replace function public.sm_list(p_coll text, p_filters jsonb default '[]', p_after text default null,
                                          p_limit int default 1000, p_order text default null, p_desc boolean default false)
returns table (id text, data jsonb, rev bigint)
language plpgsql stable security definer set search_path = public as $$
declare err text; hide text := ''; ord text;
begin
  err := public.sm_access(p_coll, '', false);
  if err is not null then raise exception '%', err using errcode = '42501'; end if;
  if p_coll in ('app_state', 'gg_state') and not public.sm_is_super() then hide := ' and d.id not in (''ggSalesPwOverride'',''sm_authpw'')'; end if;
  if p_order is null then ord := 'd.id';
  elsif p_order = '__name__' then ord := 'd.id' || case when p_desc then ' desc' else '' end;
  elsif p_order ~ '^[A-Za-z0-9_]{1,80}$' then ord := format('(d.data->>%L)', p_order) || case when p_desc then ' desc' else '' end || ', d.id';
  else raise exception 'order ไม่ถูกต้อง' using errcode = '22023'; end if;
  if jsonb_array_length(coalesce(p_filters, '[]'::jsonb)) = 0 then
    return query execute format('select d.id, d.data, d.rev from public.sm_docs d where d.coll = %L%s%s order by %s limit %s',
      p_coll, hide, case when p_after is not null then ' and d.id > ' || quote_literal(p_after) else '' end,
      ord, greatest(1, least(coalesce(p_limit, 1000), 1000)));
  else
    -- filtered: evaluate the filter first (uses the data->>'field' indexes), then page/sort the matches.
    -- Without the materialized CTE the planner may walk the whole collection in id order (2.6 s for sm_act).
    return query execute format('with m as materialized (select d.id, d.data, d.rev from public.sm_docs d where d.coll = %L%s%s) '
                                || 'select d.id, d.data, d.rev from m d where true%s order by %s limit %s',
      p_coll, hide, replace(public.sm_where(p_filters), '(data->', '(d.data->'),
      case when p_after is not null then ' and d.id > ' || quote_literal(p_after) else '' end,
      ord, greatest(1, least(coalesce(p_limit, 1000), 1000)));
  end if;
end $$;

create or replace function public.sm_count(p_coll text, p_filters jsonb default '[]') returns bigint
language plpgsql stable security definer set search_path = public as $$
declare err text; n bigint; hide text := '';
begin
  err := public.sm_access(p_coll, '', false);
  if err is not null then raise exception '%', err using errcode = '42501'; end if;
  if p_coll in ('app_state', 'gg_state') and not public.sm_is_super() then hide := ' and d.id not in (''ggSalesPwOverride'',''sm_authpw'')'; end if;
  execute format('select count(*) from public.sm_docs d where d.coll = %L%s%s', p_coll, hide, replace(public.sm_where(p_filters), '(data->', '(d.data->')) into n;
  return n;
end $$;

revoke all on function public.sm_where(jsonb), public.sm_list(text, jsonb, text, int, text, boolean), public.sm_count(text, jsonb) from anon, public;
grant execute on function public.sm_list(text, jsonb, text, int, text, boolean), public.sm_count(text, jsonb) to authenticated;
