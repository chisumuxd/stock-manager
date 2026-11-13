/* GGPLUS Stock Manager · Supabase document adapter · 2026-11-13
   Drop-in replacement for api/gg-sql-firestore.js: same window.GGSQL + fsMod API, so stock-manager.html runs unchanged.
   · data   : public.sm_docs (coll, id, data jsonb, rev) — reads through RLS, writes only through rpc sm_commit
   · live   : Supabase Realtime (one channel per collection + one for deletes) instead of polling every 20 s
   · auth   : Supabase Auth · username → <slug>@staff.bearplus.biz · profile/permissions in public.sm_users
   · legacy : fetch() calls to api/stock-manager-*.php are answered here so nothing touches the old MySQL by accident
   Needs supabase-js v2 (window.supabase) loaded first. */
(function () {
  'use strict';
  const SB_URL = 'https://zcfnbruovnxiytwehutw.supabase.co';
  const SB_KEY = 'sb_publishable_kIzay0TmKNFIipbTxMw54Q_Rqg_SbTA';
  const DOMAIN = 'staff.bearplus.biz';
  const T = 'sm_docs', PAGE = 1000;
  if (!window.supabase || !window.supabase.createClient) { console.error('[GGSUPA] supabase-js is not loaded'); return; }
  const sb = window.supabase.createClient(SB_URL, SB_KEY, { auth: { persistSession: true, autoRefreshToken: true, storageKey: 'gg-sm-supabase-auth' } });

  /* ── helpers ── */
  const slug = u => String(u || '').trim().toLowerCase().replace(/[^a-z0-9._-]+/g, '_');
  const emailOf = u => slug(u) + '@' + DOMAIN;
  const E = (msg, status, code) => { const e = new Error(msg); if (status) e.status = status; if (code) e.code = code; return e; };
  const pgErr = err => E(err.message || String(err), err.code === '42501' ? 403 : (err.code === 'P0409' || err.code === '40001') ? 409 : err.code === '28000' ? 401 : (err.status || 500), err.code);
  const ok = r => { if (r.error) throw pgErr(r.error); return r.data; };

  /* ── session ── */
  let current = null, loginResolve, waiting = new Promise(r => loginResolve = r);
  function setUser(u) { current = u; if (u) loginResolve(u); }
  async function loadProfile(uid) {
    const p = ok(await sb.from('sm_users').select('username,display_name,role,shops,perms,active').eq('user_id', uid).maybeSingle());
    if (!p || !p.active) return null;
    return { id: p.username, name: p.display_name || p.username, role: p.role, shops: Array.isArray(p.shops) ? p.shops : [], perms: p.perms && typeof p.perms === 'object' ? p.perms : {} };
  }
  async function session() {
    try {
      const { data } = await sb.auth.getSession();
      const uid = data && data.session && data.session.user && data.session.user.id;
      if (!uid) { current = null; return null; }
      const u = await loadProfile(uid);
      if (!u) { await sb.auth.signOut(); current = null; return null; }
      setUser(u); return u;
    } catch (e) { console.warn('[GGSUPA session]', e); current = null; return null; }
  }
  async function login(username, password) {
    const r = await sb.auth.signInWithPassword({ email: emailOf(username), password: String(password || '') });
    if (r.error || !r.data.user) throw E('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 401);
    const u = await loadProfile(r.data.user.id);
    if (!u) { await sb.auth.signOut(); throw E('บัญชีถูกปิดใช้งาน', 403); }
    setUser(u); return u;
  }
  async function logout() {
    try { await sb.auth.signOut(); } finally {
      current = null; waiting = new Promise(r => loginResolve = r);
      for (const h of hub.values()) try { sb.removeChannel(h.channel); } catch (_) { }
      hub.clear(); if (delChannel) { try { sb.removeChannel(delChannel); } catch (_) { } delChannel = null; }
    }
  }
  const waitAuth = () => current ? Promise.resolve(current) : waiting;
  sb.auth.onAuthStateChange((ev) => { if (ev === 'SIGNED_OUT') current = null; });

  /* ── documents ── */
  const snapDoc = (id, data, rev, exists) => ({ id, ref: { id }, metadata: { fromCache: false, hasPendingWrites: false }, revision: rev || 0,
    exists: () => exists, data: () => exists ? data : undefined, get: k => exists ? (data || {})[k] : undefined });
  function buildQuery(docs, changes) {
    const map = docs.map(d => snapDoc(d.id, d.data, d.rev, true));
    return { docs: map, size: map.length, empty: !map.length, metadata: { fromCache: false, hasPendingWrites: false },
      forEach(fn) { map.forEach(fn); }, docChanges() { return changes || map.map(doc => ({ type: 'added', doc })); } };
  }
  const operation = (op, v) => ({ __ggOp: op, ...v });
  const db = { supabase: true };
  const doc = (d, c, id) => ({ type: 'doc', collection: String(c), id: String(id) });
  const collection = (d, c) => ({ type: 'collection', collection: String(c), filters: [] });
  const query = (ref, ...filters) => ({ ...ref, filters: [...(ref.filters || []), ...filters] });
  const where = (field, op, value) => ({ type: 'where', field, op, value });
  const orderBy = (field, direction = 'asc') => ({ type: 'orderBy', field, direction });
  const limit = count => ({ type: 'limit', count });
  const startAfter = sn => ({ type: 'startAfter', id: sn && sn.id || '' });
  const colOf = f => f === '__name__' ? 'id' : 'data->>' + f;
  const txt = v => v === null || v === undefined ? null : typeof v === 'object' ? JSON.stringify(v) : String(v);
  function applyFilters(q, filters) {
    for (const f of filters || []) {
      if (f.type === 'where') {
        const col = colOf(f.field), v = f.value;
        if (f.op === '==') q = v === null ? q.is(col, null) : q.eq(col, txt(v));
        else if (f.op === '!=') q = q.neq(col, txt(v));
        else if (f.op === 'in') q = q.in(col, (v || []).map(txt));
        else if (f.op === '>=') q = q.gte(col, txt(v));
        else if (f.op === '>') q = q.gt(col, txt(v));
        else if (f.op === '<=') q = q.lte(col, txt(v));
        else if (f.op === '<') q = q.lt(col, txt(v));
        else if (f.op === 'array-contains') q = q.contains('data->' + f.field, [v]);
        else throw E('where op not supported: ' + f.op, 400);
      } else if (f.type === 'orderBy') q = q.order(colOf(f.field), { ascending: f.direction !== 'desc' });
      else if (f.type === 'limit') q = q.limit(f.count);
      else if (f.type === 'startAfter' && f.id) q = q.gt('id', f.id);
    }
    return q;
  }
  function matches(d, filters) {            // same rules, evaluated in the browser for realtime rows
    for (const f of filters || []) {
      if (f.type !== 'where') continue;
      const raw = f.field === '__name__' ? d.id : (d.data || {})[f.field], a = txt(raw), b = txt(f.value);
      if (f.op === '==' && !(f.value === null ? raw == null : a === b)) return false;
      if (f.op === '!=' && a === b) return false;
      if (f.op === 'in' && !(f.value || []).map(txt).includes(a)) return false;
      if (f.op === '>=' && !(a !== null && a >= b)) return false;
      if (f.op === '>' && !(a !== null && a > b)) return false;
      if (f.op === '<=' && !(a !== null && a <= b)) return false;
      if (f.op === '<' && !(a !== null && a < b)) return false;
      if (f.op === 'array-contains' && !(Array.isArray(raw) && raw.some(x => JSON.stringify(x) === JSON.stringify(f.value)))) return false;
    }
    return true;
  }
  async function getDoc(r) {
    const row = ok(await sb.from(T).select('data,rev').eq('coll', r.collection).eq('id', r.id).maybeSingle());
    return snapDoc(r.id, row ? row.data : undefined, row ? row.rev : 0, !!row);
  }
  // reads of whole/filtered collections go through rpc sm_list / sm_count (collection-level permission check once,
  // then indexed SQL) — plain table reads under RLS cannot use the data->>'field' indexes
  const whereList = filters => (filters || []).filter(f => f.type === 'where').map(f => ({ field: f.field, op: f.op, value: f.value === undefined ? null : f.value }));
  async function list(q) {
    const filters = q.filters || [], w = whereList(filters);
    const ob = filters.find(f => f.type === 'orderBy'), lim = filters.find(f => f.type === 'limit'), sa = filters.find(f => f.type === 'startAfter');
    if (ob || lim) return ok(await sb.rpc('sm_list', { p_coll: q.collection, p_filters: w, p_after: sa && sa.id || null,
      p_limit: lim ? Math.min(lim.count, PAGE) : PAGE, p_order: ob ? ob.field : null, p_desc: !!(ob && ob.direction === 'desc') }));
    const out = []; let last = sa && sa.id || null;
    for (;;) {                                           // keyset paging by id (max 1000 rows per call)
      const rows = ok(await sb.rpc('sm_list', { p_coll: q.collection, p_filters: w, p_after: last, p_limit: PAGE }));
      out.push(...rows);
      if (rows.length < PAGE) break; last = rows[rows.length - 1].id;
    }
    return out;
  }
  const getDocs = async q => buildQuery(await list(q));
  async function getCountFromServer(q) {
    const n = ok(await sb.rpc('sm_count', { p_coll: q.collection, p_filters: whereList(q.filters) }));
    return { data: () => ({ count: Number(n) || 0 }) };
  }
  const commit = async (ops, checks) => ok(await sb.rpc('sm_commit', { p_ops: ops, p_checks: checks || {} }));
  const opOf = (ref, data, o = {}) => ({ collection: ref.collection, id: ref.id, data: data || {}, merge: !!o.merge, ...(o.mergeFields ? { mergeFields: o.mergeFields } : {}) });
  const setDoc = (ref, data, o = {}) => commit([opOf(ref, data, o)]);
  const deleteDoc = ref => commit([{ collection: ref.collection, id: ref.id, type: 'delete' }]);
  function writeBatch() {
    const ops = [];
    return { set(ref, data, o = {}) { ops.push(opOf(ref, data, o)); return this; },
      update(ref, data) { ops.push(opOf(ref, data, { merge: true })); return this; },
      delete(ref) { ops.push({ collection: ref.collection, id: ref.id, type: 'delete' }); return this; },
      async commit() { for (let i = 0; i < ops.length; i += 400) await commit(ops.slice(i, i + 400)); } };
  }
  async function runTransaction(_db, fn) {
    for (let attempt = 0; attempt < 3; attempt++) {
      const reads = {}, ops = [];
      const tx = { async get(ref) { const s = await getDoc(ref); reads[ref.collection + '/' + ref.id] = s.revision; return s; },
        set(ref, data, o = {}) { ops.push(opOf(ref, data, o)); return tx; },
        update(ref, data) { ops.push(opOf(ref, data, { merge: true })); return tx; },
        delete(ref) { ops.push({ collection: ref.collection, id: ref.id, type: 'delete' }); return tx; } };
      const result = await fn(tx); if (!ops.length) return result;
      try { await commit(ops, reads); return result; }
      catch (e) { if (e.status !== 409 || attempt === 2) throw e; }
    }
  }

  /* ── realtime: one channel per collection (insert/update) + one shared channel for deletes ── */
  const hub = new Map(); let delChannel = null;
  function channelFor(coll) {
    let h = hub.get(coll); if (h) return h;
    h = { listeners: new Set(), status: 'new' };
    const onRow = p => { const n = p.new || {}; deliver(coll, 'up', n.id, n); };
    h.channel = sb.channel('sm:' + coll)
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: T, filter: 'coll=eq.' + coll }, onRow)
      .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: T, filter: 'coll=eq.' + coll }, onRow)
      .subscribe(st => {
        const was = h.status; h.status = st;
        if (st === 'SUBSCRIBED') { h.ready = true; if (was === 'CHANNEL_ERROR' || was === 'TIMED_OUT' || was === 'CLOSED') h.listeners.forEach(l => l.resync()); }
      });
    if (!delChannel) delChannel = sb.channel('sm:deletes')
      .on('postgres_changes', { event: 'DELETE', schema: 'public', table: T }, p => { const o = p.old || {}; if (o.coll) deliver(o.coll, 'del', o.id, o); })
      .subscribe();
    hub.set(coll, h); return h;
  }
  function deliver(coll, kind, id, row) { const h = hub.get(coll); if (h) h.listeners.forEach(l => l.event(kind, id, row)); }
  function release(coll, l) {
    const h = hub.get(coll); if (!h) return; h.listeners.delete(l);
    if (!h.listeners.size) { try { sb.removeChannel(h.channel); } catch (_) { } hub.delete(coll); }
  }
  function onSnapshot(ref, opts, success, error) {
    if (typeof opts === 'function' || (opts && opts.next)) { error = success; success = opts; opts = {}; }
    if (success && typeof success === 'object') { error = success.error; success = success.next; }
    const fail = e => { if (error) error(e); else console.warn('[GGSUPA realtime]', e); };
    let stopped = false, loaded = false; const buffer = [];
    const l = {};
    if (ref.type === 'doc') {
      let rev = -1;
      const emit = (data, r, exists) => { if (stopped) return; if (exists && r === rev) return; rev = exists ? r : -1; success(snapDoc(ref.id, data, r, exists)); };
      const refetch = () => getDoc(ref).then(s => emit(s.data(), s.revision, s.exists())).catch(fail);
      l.event = (kind, id, row) => {
        if (id !== ref.id) return;
        if (!loaded) { buffer.push([kind, row]); return; }
        if (kind === 'del') emit(undefined, 0, false);
        else if (row.data === undefined) refetch();                       // payload too large for realtime → read it
        else if (row.rev > rev) emit(row.data, row.rev, true);
      };
      l.resync = refetch;
      const h = channelFor(ref.collection); h.listeners.add(l);
      getDoc(ref).then(s => { loaded = true; emit(s.data(), s.revision, s.exists()); buffer.splice(0).forEach(([k, row]) => l.event(k, row.id, row)); }).catch(fail);
    } else {
      const map = new Map(); let pending = [], timer = null;
      const flush = () => { timer = null; if (stopped || !pending.length) return; const ch = pending; pending = []; success(buildQuery([...map.values()], ch)); };
      const queue = c => { pending.push(c); if (!timer) timer = setTimeout(flush, 40); };
      const apply = (kind, id, row) => {
        const old = map.get(id);
        if (kind === 'del') { if (old) { map.delete(id); queue({ type: 'removed', doc: snapDoc(id, old.data, old.rev, true) }); } return; }
        if (row.data === undefined) { getDoc({ collection: ref.collection, id }).then(s => { if (s.exists()) apply('up', id, { id, data: s.data(), rev: s.revision }); else apply('del', id, row); }).catch(fail); return; }
        const d = { id, data: row.data, rev: row.rev };
        if (!matches(d, ref.filters)) { if (old) { map.delete(id); queue({ type: 'removed', doc: snapDoc(id, old.data, old.rev, true) }); } return; }
        if (old && old.rev >= d.rev) return;
        map.set(id, d); queue({ type: old ? 'modified' : 'added', doc: snapDoc(id, d.data, d.rev, true) });
      };
      l.event = (kind, id, row) => { if (!loaded) buffer.push([kind, id, row]); else apply(kind, id, row); };
      l.resync = () => list(ref).then(rows => {                          // after a reconnect: diff against the server
        const seen = new Set();
        rows.forEach(r => { seen.add(r.id); apply('up', r.id, r); });
        [...map.keys()].forEach(id => { if (!seen.has(id)) apply('del', id, { id }); });
      }).catch(fail);
      const h = channelFor(ref.collection); h.listeners.add(l);
      list(ref).then(rows => {
        if (stopped) return;
        rows.forEach(r => map.set(r.id, { id: r.id, data: r.data, rev: r.rev }));
        loaded = true; success(buildQuery([...map.values()]));
        buffer.splice(0).forEach(([k, id, row]) => apply(k, id, row));
      }).catch(fail);
    }
    return () => { stopped = true; release(ref.collection, l); };
  }

  /* ── server checks used at boot ── */
  function canSeeShop(svc) {
    const u = current; if (!u) return false; if (u.role === 'super') return true;
    if (u.perms && u.perms.smAll === true) return true;
    return (u.shops || []).some(s => s === '*' || String(s).toLowerCase() === String(svc).toLowerCase());
  }
  async function probe(service = 'netflix') {
    await waitAuth();
    const coll = 'sm_' + service + '_accounts';
    const deny = ok(await sb.rpc('sm_access', { p_coll: coll, p_id: '', p_write: false }));
    if (deny) throw E(deny, 403);
    const all = await getCountFromServer({ collection: coll, filters: [] });
    const tomb = await getCountFromServer({ collection: coll, filters: [where('x', '==', true)] });
    return { ok: true, mysql: true, source: 'supabase', service, accounts: all.data().count - tomb.data().count, documents: all.data().count, server_time: new Date().toISOString() };
  }
  async function gunzipB64(b64) {
    const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return await new Response(new Blob([bin]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  }
  async function decodeValue(raw) {
    let v = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw.value !== undefined ? raw.value : raw.v) : raw;
    if (typeof v === 'string') { try { v = JSON.parse(v.startsWith('GZ:') ? await gunzipB64(v.slice(3)) : v); } catch (_) { v = null; } }
    return Array.isArray(v) ? v : null;
  }
  async function inventory() {                    // same merge rules as stock-manager-inventory.php (without the old fs_* snapshots)
    await waitAuth();
    const counts = {}; ok(await sb.rpc('sm_counts', {})).forEach(r => { counts[r.coll.slice(3, -9)] = Number(r.docs); });
    const pick = {};
    for (const key of ['sm_apps', 'sm_svc_registry', 'sm_svc_removed']) {
      const merged = [], idx = new Map();
      for (const c of ['app_state', 'app_state_v2']) {
        const s = await getDoc({ collection: c, id: key }); if (!s.exists()) continue;
        const value = await decodeValue(s.data()); if (!value) continue;
        for (const entry of value) {
          if (key === 'sm_svc_removed') { if (typeof entry === 'string' && /^[a-z0-9_-]{2,70}$/.test(entry) && !idx.has(entry)) { idx.set(entry, merged.length); merged.push(entry); } continue; }
          if (!entry || typeof entry !== 'object') continue;
          const svc = String(entry[key === 'sm_apps' ? 'link' : 'key'] || '');
          if (svc && (!/^[a-z0-9_-]{2,70}$/.test(svc) || !canSeeShop(svc))) continue;
          const id = String(entry[key === 'sm_apps' ? 'id' : 'key'] || ''); if (!id) continue;
          const ident = svc ? 'svc:' + svc : 'id:' + id;
          if (!idx.has(ident)) { idx.set(ident, merged.length); merged.push(entry); }
          else { const at = idx.get(ident), before = merged[at]; merged[at] = { ...before, ...entry }; if (key === 'sm_apps' && !entry.icon && before.icon) merged[at].icon = before.icon; }
        }
      }
      pick[key] = merged;
    }
    const removed = new Set(pick.sm_svc_removed);
    const apps = pick.sm_apps.filter(a => !removed.has(String(a.link || '')));
    const registry = [], known = new Set(['netflix', 'disney']);
    for (const v of pick.sm_svc_registry) { const s = String(v.key || ''); if (!s || removed.has(s) || known.has(s)) continue; known.add(s); registry.push(v); }
    for (const a of apps) { const s = String(a.link || ''); if (!s || removed.has(s) || known.has(s)) continue; known.add(s); registry.push({ key: s, name: String(a.name || s) }); }
    for (const s of Object.keys(counts)) { if (known.has(s) || removed.has(s)) continue; known.add(s); registry.push({ key: s, name: s }); }
    return { ok: true, mysql: true, source: 'supabase', apps, registry, removed: pick.sm_svc_removed, counts, potential_gap: false,
      app_count: apps.length, service_count: registry.length + 2 };
  }

  /* ── GGSQL.request(action) used directly by the page ── */
  async function request(action, args, body) {
    await waitAuth();
    if (action === 'preflight') return { ok: true };
    if (action === 'session') return { ok: true, user: current, csrf: '' };
    if (action === 'usersAdminList') {
      if (current.role !== 'super') throw E('เฉพาะแอดมินสูงสุด', 403);
      const rows = ok(await sb.from('sm_users').select('username,display_name,role,shops,perms,active').order('username'));
      return { ok: true, users: rows.map(u => ({ ...u, password_setup_pending: false })), legacy_users: [] };
    }
    if (action === 'usersAdminWrite') return ok(await sb.rpc('sm_admin_user', { p: body || {} }));
    if (action === 'usersAdminSyncLegacy') return { ok: true, inserted: 0, awaiting_password: 0, skipped: 0 };
    if (action === 'changePassword') {
      const b = body || {}, nw = String(b.new || '');
      if (nw.length < 8) throw E('รหัสผ่านใหม่ต้องมีอย่างน้อย 8 ตัวอักษร', 422);
      const chk = await sb.auth.signInWithPassword({ email: emailOf(current.id), password: String(b.current || '') });
      if (chk.error) throw E('รหัสผ่านเดิมไม่ถูกต้อง', 403);
      const up = await sb.auth.updateUser({ password: nw }); if (up.error) throw E(up.error.message, 400);
      return { ok: true };
    }
    throw E('ไม่รองรับคำสั่ง ' + action + ' บน Supabase', 400);
  }

  /* ── old PHP endpoints the page still fetch()es: answer here (never reach the old MySQL) ── */
  const _fetch = window.fetch.bind(window);
  const jsonRes = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json' } });
  async function exportAll() {                     // super: every document the account can read, as one JSON download
    await waitAuth(); if (current.role !== 'super') return jsonRes({ ok: false, error: 'เฉพาะ Super Admin' }, 403);
    const colls = new Set(); let last = null;
    for (;;) { let b = sb.from(T).select('coll').order('coll').limit(1); if (last !== null) b = b.gt('coll', last); const r = ok(await b); if (!r.length) break; last = r[0].coll; colls.add(last); }
    const parts = ['{"source":"supabase","exported_at":', JSON.stringify(new Date().toISOString()), ',"collections":{'];
    let first = true;
    for (const c of colls) {
      const rows = await list({ collection: c, filters: [] });
      parts.push((first ? '' : ',') + JSON.stringify(c) + ':' + JSON.stringify(Object.fromEntries(rows.map(r => [r.id, r.data])))); first = false;
    }
    parts.push('}}');
    return new Response(new Blob(parts, { type: 'application/json' }), { status: 200 });
  }
  window.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    const m = url.match(/api\/stock-manager-(avatars|export|restore-all|restore|repair|probe|inventory)\.php/);
    if (!m) return _fetch(input, init);
    if (m[1] === 'avatars') return Promise.resolve(jsonRes({ ok: true, total: 0, inserted: {}, legacy_available: {} }));
    if (m[1] === 'export') return exportAll();
    return Promise.resolve(jsonRes({ ok: false, error: 'ย้ายไป Supabase แล้ว — ใช้ระบบสำรองข้อมูลของ Supabase แทน' }, 410));
  };
  document.addEventListener('DOMContentLoaded', () => { const b = document.getElementById('btnSqlInventory'); if (b) b.style.display = 'none'; });

  const fsMod = { doc, collection, query, where, orderBy, limit, startAfter, getDoc, getDocs, getCountFromServer, setDoc, deleteDoc, runTransaction, writeBatch, onSnapshot,
    serverTimestamp: () => operation('timestamp', {}), deleteField: () => operation('deleteField', {}), increment: amount => operation('increment', { amount }),
    arrayUnion: (...items) => operation('arrayUnion', { items }), arrayRemove: (...items) => operation('arrayRemove', { items }),
    FieldPath: { documentId: () => '__name__' }, getFirestore: () => db };
  window.GGSQL = { request, session, login, logout, waitAuth, probe, inventory, supabase: sb,
    adapter: async () => { await waitAuth(); return { db, fsMod }; }, get user() { return current; }, get csrf() { return ''; } };
  session().then(user => { if (user && typeof window.ggSqlShowSession === 'function') window.ggSqlShowSession(user); });
})();
