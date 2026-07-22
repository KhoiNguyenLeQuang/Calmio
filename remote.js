/* ============================================================
   Calmio remote adapter (Supabase)
   ------------------------------------------------------------
   Design: the rest of the app keeps reading synchronously from an
   in-memory cache shaped exactly like the local stores. This file:

   1. Signs users in/up with Supabase Auth (session kept in
      sessionStorage, so closing the tab still signs you out).
   2. On sign-in, loads everything the user is ALLOWED to see
      (enforced by Row Level Security) into the cache.
   3. On every DB.write, diffs the new store value against the last
      known value and pushes only row-level inserts / updates /
      deletes - so two counselors working at once don't overwrite
      each other's rows.
   4. Polls for fresh data every 15s and on window focus.

   Known limit (documented in README): editing the SAME row at the
   same moment (e.g. two counselors replying to one thought in the
   same second) is last-write-wins. For a school-sized service this
   is fine; upgrade path is Supabase Realtime + per-reply rows.
   ============================================================ */

/* Supabase's client keeps the session in localStorage by default;
   Calmio wants sessions to end when the page closes. */
const _sessionStore = {
  getItem: k => sessionStorage.getItem(k),
  setItem: (k, v) => sessionStorage.setItem(k, v),
  removeItem: k => sessionStorage.removeItem(k)
};

const Remote = {
  on: false,
  sb: null,
  cache: {},          // store name -> app-shaped value
  _last: {},          // last pushed/loaded snapshot, for diffing
  _pollTimer: null,

  /* ---------- setup ---------- */
  configure() {
    const cfg = window.CALMIO_REMOTE || {};
    if (!cfg.url || !cfg.anonKey || !window.supabase) return false;
    this.sb = window.supabase.createClient(cfg.url, cfg.anonKey, {
      auth: { storage: _sessionStore, persistSession: true, autoRefreshToken: true }
    });
    this.on = true;
    return true;
  },

  async init() {
    const { data } = await this.sb.auth.getSession();
    this.session = data.session || null;
    return this.session;
  },

  uid() { return this.session ? this.session.user.id : null; },

  /* ---------- auth ---------- */
  async emailFor(identifier) {
    if (identifier.includes("@")) return identifier;
    const { data, error } = await this.sb.rpc("email_for_username", { u: identifier });
    if (error || !data) return null;
    return data;
  },

  async signIn(identifier, password) {
    const email = await this.emailFor(identifier.trim().toLowerCase());
    if (!email) return { error: "That username/email and password don't match." };
    const { data, error } = await this.sb.auth.signInWithPassword({ email, password });
    if (error) {
      const msg = /rate|too many/i.test(error.message)
        ? "Too many attempts - please wait a minute and try again."
        : "That username/email and password don't match.";
      return { error: msg };
    }
    this.session = data.session;
    return { ok: true };
  },

  async usernameTaken(username) {
    const { data } = await this.sb.rpc("username_taken", { u: username });
    return !!data;
  },

  async signUp({ username, email, fullname, school, password }) {
    if (await this.usernameTaken(username))
      return { error: "That username is already taken - try another." };
    const { data, error } = await this.sb.auth.signUp({
      email, password,
      options: { data: { username, full_name: fullname, school } }
    });
    if (error) {
      const msg = /already registered/i.test(error.message)
        ? "An account with that email already exists."
        : error.message;
      return { error: msg };
    }
    if (!data.session) return { confirm: true };   // email confirmation is on
    this.session = data.session;
    return { ok: true };
  },

  async reauth(password) {
    const email = this.session && this.session.user.email;
    if (!email) return false;
    const { error } = await this.sb.auth.signInWithPassword({ email, password });
    return !error;
  },

  async changePassword(currentPass, newPass) {
    if (!(await this.reauth(currentPass))) return { error: "Current password is wrong." };
    const { error } = await this.sb.auth.updateUser({ password: newPass });
    return error ? { error: error.message } : { ok: true };
  },

  async signOut() {
    this.stopPolling();
    try { await this.sb.auth.signOut(); } catch {}
    this.session = null;
    this.cache = {};
    this._last = {};
  },

  /* Calls a Netlify function that holds the service-role key. */
  async _service(path, payload) {
    const res = await fetch("/api/" + path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + (this.session ? this.session.access_token : "")
      },
      body: JSON.stringify(payload || {})
    });
    let body = {};
    try { body = await res.json(); } catch {}
    if (!res.ok) return { error: body.error || ("Request failed (" + res.status + ")") };
    return body;
  },

  staff(payload) { return this._service("staff", payload); },
  deleteAccount() { return this._service("delete-account"); },

  /* ---------- loading: server rows -> app-shaped cache ---------- */
  _profileToUser(row) {
    return {
      id: row.id, name: row.username, email: row.email || "",
      display: row.display, role: row.role,
      anonId: row.anon_code || undefined,
      profile: row.profile || {}
    };
  },

  me() {
    const users = this.cache.calmio_users || [];
    return users.find(u => u.id === this.uid()) || null;
  },

  async loadAll() {
    const sb = this.sb;
    const grab = async (q) => { const { data, error } = await q; return error ? [] : (data || []); };
    const [profiles, thoughts, loves, articles, bookings, notes, testimonials,
           feedback, reports, settings, gardens, busy] = await Promise.all([
      grab(sb.from("profiles").select("*")),
      grab(sb.from("thoughts").select("*")),
      grab(sb.from("loves").select("*")),
      grab(sb.from("articles").select("*")),
      grab(sb.from("bookings").select("*")),
      grab(sb.from("notes").select("*")),
      grab(sb.from("testimonials").select("*")),
      grab(sb.from("feedback").select("*")),
      grab(sb.from("reports").select("*")),
      grab(sb.from("app_settings").select("*")),
      grab(sb.from("gardens").select("*")),
      grab(sb.rpc("busy_slots"))
    ]);

    const dataOf = rows => rows.map(r => r.data);
    const visibleSlots = dataOf(bookings);
    const visibleKeys = new Set(visibleSlots.map(s => s.teacherId + "|" + s.start));
    // Other students' bookings arrive as anonymous "busy" markers so the
    // weekly grid can gray them out without exposing who booked.
    const busySlots = (busy || [])
      .filter(b => !visibleKeys.has(b.teacher_id + "|" + Number(b.start)))
      .map((b, i) => ({ id: "busy_" + i, teacherId: b.teacher_id, start: Number(b.start) }));

    const notesMap = {};    notes.forEach(r => { notesMap[r.key] = r.data; });
    const gardenMap = {};   gardens.forEach(r => { gardenMap[r.id] = r.data; });

    this.cache = {
      calmio_users:        profiles.map(this._profileToUser),
      calmio_thoughts:     dataOf(thoughts),
      calmio_loves:        dataOf(loves),
      calmio_articles:     dataOf(articles),
      calmio_slots:        visibleSlots.concat(busySlots),
      calmio_notes:        notesMap,
      calmio_testimonials: dataOf(testimonials),
      calmio_feedback:     dataOf(feedback),
      calmio_reports:      dataOf(reports),
      calmio_settings:     (settings[0] && settings[0].data) || undefined,
      calmio_garden:       gardenMap,
      calmio_lockouts:     {}
    };
    this._snapshot();
    return this.cache;
  },

  _snapshot() {
    this._last = JSON.parse(JSON.stringify(this.cache));
  },

  /* ---------- writing: diff the store, push row-level changes ---------- */

  /* Extra indexed columns each table needs for Row Level Security. */
  _cols: {
    calmio_thoughts: (d, uid) => ({ author: d.fromId, anonymous: !!d.anonymous }),
    calmio_loves:    (d, uid) => ({ author: uid, to_id: d.toId || null }),
    calmio_articles: (d, uid) => ({ author: uid }),
    calmio_slots:    (d, uid) => ({ teacher_id: d.teacherId, booked_by: d.bookedBy || null }),
    calmio_testimonials: (d, uid) => ({ author: uid }),
    calmio_feedback: (d, uid) => ({ author: uid }),
    calmio_reports:  (d, uid) => ({ author: uid })
  },
  _tables: {
    calmio_thoughts: "thoughts", calmio_loves: "loves", calmio_articles: "articles",
    calmio_slots: "bookings", calmio_testimonials: "testimonials",
    calmio_feedback: "feedback", calmio_reports: "reports"
  },

  _pending: 0,
  push(store, value) {
    if (!this.on || !this.session) return;
    const prev = this._last[store];
    const p = this._pushOps(store, value, prev);
    this._last[store] = JSON.parse(JSON.stringify(value));
    if (p) {
      this._pending++;
      p.catch(() => app.toast("Saving to the server failed - check your connection."))
       .finally(() => { this._pending = Math.max(0, this._pending - 1); });
    }
  },

  _pushOps(store, value, prev) {
    const sb = this.sb, uid = this.uid();

    /* users -> own profile row (username/email/role handled elsewhere) */
    if (store === "calmio_users") {
      const mine = (value || []).find(u => u.id === uid);
      const before = (prev || []).find(u => u.id === uid);
      if (!mine || JSON.stringify(mine) === JSON.stringify(before)) return null;
      return sb.from("profiles").update({
        display: mine.display, profile: mine.profile || {}
      }).eq("id", uid).then(({ error }) => { if (error) throw error; });
    }

    /* single settings row */
    if (store === "calmio_settings") {
      if (JSON.stringify(value) === JSON.stringify(prev)) return null;
      return sb.from("app_settings").upsert({ key: "main", data: value })
        .then(({ error }) => { if (error) throw error; });
    }

    /* keyed maps: notes / gardens */
    if (store === "calmio_notes" || store === "calmio_garden") {
      const table = store === "calmio_notes" ? "notes" : "gardens";
      const idcol = store === "calmio_notes" ? "key" : "id";
      const ops = [];
      const v = value || {}, pv = prev || {};
      for (const k of Object.keys(v)) {
        if (JSON.stringify(v[k]) !== JSON.stringify(pv[k]))
          ops.push(sb.from(table).upsert({ [idcol]: k, data: v[k] }));
      }
      for (const k of Object.keys(pv)) {
        if (!(k in v)) ops.push(sb.from(table).delete().eq(idcol, k));
      }
      return ops.length ? Promise.all(ops).then(rs => {
        const bad = rs.find(r => r.error); if (bad) throw bad.error;
      }) : null;
    }

    /* array stores: diff by record id */
    const table = this._tables[store];
    if (!table) return null;
    const colsFor = this._cols[store] || (() => ({}));
    const v = value || [], pv = prev || [];
    const prevById = new Map(pv.map(r => [r.id, r]));
    const nowIds = new Set(v.map(r => r.id));
    const ops = [];
    for (const rec of v) {
      if (String(rec.id).startsWith("busy_")) continue;      // synthetic markers
      const before = prevById.get(rec.id);
      if (!before || JSON.stringify(before) !== JSON.stringify(rec)) {
        ops.push(sb.from(table).upsert({ id: rec.id, ...colsFor(rec, uid), data: rec }));
      }
    }
    for (const rec of pv) {
      if (String(rec.id).startsWith("busy_")) continue;
      if (!nowIds.has(rec.id)) ops.push(sb.from(table).delete().eq("id", rec.id));
    }
    return ops.length ? Promise.all(ops).then(rs => {
      const bad = rs.find(r => r.error); if (bad) throw bad.error;
    }) : null;
  },

  /* ---------- keeping fresh ---------- */
  startPolling(onChange) {
    this.stopPolling();
    const tick = async () => {
      if (!this.session || this._pending > 0) return;   // never clobber in-flight writes
      const before = JSON.stringify(this.cache);
      try { await this.loadAll(); } catch { return; }
      if (JSON.stringify(this.cache) !== before) onChange();
    };
    this._pollTimer = setInterval(tick, 15000);
    this._onFocus = () => tick();
    window.addEventListener("focus", this._onFocus);
  },
  stopPolling() {
    if (this._pollTimer) clearInterval(this._pollTimer);
    if (this._onFocus) window.removeEventListener("focus", this._onFocus);
    this._pollTimer = null; this._onFocus = null;
  }
};
