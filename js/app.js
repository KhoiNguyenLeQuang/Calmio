/* ============================================================
   Calmio - app logic

   Security model (client-side, defense in depth):
   - ALL app data is encrypted at rest with AES-256-GCM before it
     touches localStorage. The encryption key is a NON-EXTRACTABLE
     WebCrypto key kept in IndexedDB, so the key material itself can
     never be read out as bytes. Anyone who copies localStorage gets
     only ciphertext.
   - Passwords are never stored: only a salted PBKDF2-SHA256 hash
     (150,000 rounds). Old SHA-256 hashes are upgraded silently on
     the next successful sign-in.
   - 5 failed sign-ins -> 60-second lockout (stops password guessing)
   - Auto-lock after N minutes of inactivity
   - Every piece of user text is escaped before rendering (XSS), and
     a strict Content-Security-Policy in index.html blocks foreign
     scripts and blocks data from being sent to any other domain.

   NOTE: true protection for a real school deployment still requires
   a server (see README). This file makes the browser copy of the
   data as hard to steal as a static site can.
   ============================================================ */

/* ---------------- Encrypted vault ----------------
   One encrypted blob (calmio_vault) holds every store. Reads and
   writes go through an in-memory cache so the rest of the app can
   stay synchronous; the cache is re-encrypted and persisted after
   every write. */
const VAULT_STORES = [
  "calmio_users", "calmio_articles", "calmio_thoughts", "calmio_loves",
  "calmio_slots", "calmio_testimonials", "calmio_feedback",
  "calmio_settings", "calmio_lockouts", "calmio_notes", "calmio_reports", "calmio_garden"
];

const Vault = {
  cache: {},
  key: null,
  plain: false,          // fallback mode for very old browsers
  _persisting: null,

  async init() {
    try {
      if (!(window.crypto && crypto.subtle && window.indexedDB)) throw new Error("no crypto");
      this.key = await this._getKey();
      const blob = localStorage.getItem("calmio_vault");
      if (blob) {
        this.cache = await this._decrypt(JSON.parse(blob));
      }
    } catch (e) {
      // Last-resort fallback: unencrypted (never expected on modern browsers)
      this.plain = true;
      try { this.cache = JSON.parse(localStorage.getItem("calmio_vault_plain")) || {}; }
      catch { this.cache = {}; }
    }
    this._migrateLegacy();
  },

  /* Move any pre-encryption plaintext calmio_* keys into the vault,
     then delete the plaintext copies. */
  _migrateLegacy() {
    let moved = false;
    for (const k of VAULT_STORES) {
      const raw = localStorage.getItem(k);
      if (raw !== null) {
        try { if (this.cache[k] === undefined) this.cache[k] = JSON.parse(raw); } catch {}
        localStorage.removeItem(k);
        moved = true;
      }
    }
    if (moved) this.persist();
  },

  /* Non-extractable AES-GCM key living in IndexedDB */
  _getKey() {
    return new Promise((resolve, reject) => {
      const open = indexedDB.open("calmio-secure", 1);
      open.onupgradeneeded = () => open.result.createObjectStore("keys");
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result;
        const get = db.transaction("keys", "readonly").objectStore("keys").get("vault-key");
        get.onerror = () => reject(get.error);
        get.onsuccess = async () => {
          if (get.result) { resolve(get.result); return; }
          try {
            const key = await crypto.subtle.generateKey(
              { name: "AES-GCM", length: 256 }, /* extractable: */ false,
              ["encrypt", "decrypt"]);
            const put = db.transaction("keys", "readwrite").objectStore("keys").put(key, "vault-key");
            put.onerror = () => reject(put.error);
            put.onsuccess = () => resolve(key);
          } catch (e) { reject(e); }
        };
      };
    });
  },

  async _encrypt(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(JSON.stringify(obj));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, this.key, data);
    const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
    return { v: 1, iv: b64(iv), ct: b64(ct) };
  },

  async _decrypt(blob) {
    const bytes = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes(blob.iv) }, this.key, bytes(blob.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  },

  persist() {
    if (this.plain) {
      localStorage.setItem("calmio_vault_plain", JSON.stringify(this.cache));
      return;
    }
    // Serialize writes so persists never interleave
    this._persisting = (this._persisting || Promise.resolve()).then(async () => {
      const blob = await this._encrypt(this.cache);
      localStorage.setItem("calmio_vault", JSON.stringify(blob));
    }).catch(() => {});
  }
};

const DB = {
  /* In remote (Supabase) mode the cache lives in Remote.cache and every
     write is diffed into row-level operations against the database.
     In local mode nothing changes: encrypted vault in this browser. */
  _c() { return Remote.on ? Remote.cache : Vault.cache; },
  read(key, fallback) {
    const v = this._c()[key];
    if (v === undefined || v === null) return fallback;
    return JSON.parse(JSON.stringify(v));           // hand out copies, never live refs
  },
  write(key, value) {
    this._c()[key] = JSON.parse(JSON.stringify(value));
    if (Remote.on) Remote.push(key, value);
    else Vault.persist();
  },
  remove(key) {
    delete this._c()[key];
    if (!Remote.on) Vault.persist();
  }
};

const uid = () => Math.random().toString(36).slice(2, 10);
const now = () => Date.now();

function timeAgo(ts) {
  const s = Math.floor((now() - ts) / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);   if (m < 60) return m + "m ago";
  const h = Math.floor(m / 60);   if (h < 24) return h + "h ago";
  const d = Math.floor(h / 24);   if (d < 7)  return d + "d ago";
  return Math.floor(d / 7) + "w ago";
}

/* XSS protection: every piece of user text goes through esc() before
   being placed into innerHTML anywhere in this file. */
function esc(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

/* ---------- Password hashing (PBKDF2, never store plain text) ---------- */
const PBKDF2_ITER = 150000;

async function pbkdf2(password, salt, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations },
    keyMaterial, 256);
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Legacy(password, salt) {
  const data = new TextEncoder().encode(salt + "::" + password);
  if (window.crypto && crypto.subtle) {
    const buf = await crypto.subtle.digest("SHA-256", data);
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  }
  let h1 = 0x811c9dc5, h2 = 0x01000193;
  for (const b of data) { h1 = (h1 ^ b) * 16777619 >>> 0; h2 = (h2 + b) * 31 >>> 0; }
  return h1.toString(16) + h2.toString(16);
}

async function makeHash(password, salt) {
  if (window.crypto && crypto.subtle) {
    return "pbkdf2$" + PBKDF2_ITER + "$" + await pbkdf2(password, salt, PBKDF2_ITER);
  }
  return await sha256Legacy(password, salt);        // ancient-browser fallback
}

/* Verifies against PBKDF2 or a legacy SHA-256 hash; returns
   { ok, upgraded } - upgraded=true means user object was rewritten
   with a fresh PBKDF2 hash and should be saved. */
async function verifyPass(user, password) {
  const stored = user.passHash || "";
  if (stored.startsWith("pbkdf2$")) {
    const [, iter, hex] = stored.split("$");
    const test = await pbkdf2(password, user.salt || "", parseInt(iter, 10) || PBKDF2_ITER);
    return { ok: test === hex, upgraded: false };
  }
  const ok = (await sha256Legacy(password, user.salt || "")) === stored;
  if (ok && window.crypto && crypto.subtle) {
    user.salt = newSalt();
    user.passHash = await makeHash(password, user.salt);
    return { ok: true, upgraded: true };
  }
  return { ok, upgraded: false };
}

const newSalt = () => uid() + uid();

/* ---------- Sign-in lockout (anti brute-force) ---------- */
const LOCK_MAX_FAILS = 5;
const LOCK_SECONDS = 60;
function lockKey(id) { return id.trim().toLowerCase(); }
function getLockout(id) {
  const all = DB.read("calmio_lockouts", {});
  return all[lockKey(id)] || { fails: 0, until: 0 };
}
function setLockout(id, rec) {
  const all = DB.read("calmio_lockouts", {});
  all[lockKey(id)] = rec;
  DB.write("calmio_lockouts", all);
}

/* Display name: full name if set, else the username */
const disp = u => (u && (u.display || u.name)) || "";

/* Known school email domains -> school names. Add your school here so the
   sign-up form fills the school automatically from the email address. */
const SCHOOL_DOMAINS = {
  "hanoihigh.edu.vn": "Hanoi High"
};
function schoolFromEmail(email) {
  const at = email.indexOf("@");
  if (at < 0) return "";
  const domain = email.slice(at + 1).toLowerCase().trim();
  if (SCHOOL_DOMAINS[domain]) return SCHOOL_DOMAINS[domain];
  // Generic guess: strip common suffixes and prettify ("truonghighschool.edu.vn" -> "Truonghighschool")
  const core = domain.replace(/\.(edu|ac|k12|sch|school)?\.?(vn|com|org|net|edu)$/i, "");
  if (!core || core.includes(".") || ["gmail", "yahoo", "outlook", "hotmail", "icloud", "proton", "protonmail"].includes(core)) return "";
  return core.charAt(0).toUpperCase() + core.slice(1);
}
const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,19}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/* Stable anonymous code name, e.g. #student4271 */
function newAnonId() {
  const used = new Set(DB.read("calmio_users", []).map(u => u.anonId).filter(Boolean));
  let id;
  do { id = "student" + String(Math.floor(1000 + Math.random() * 9000)); } while (used.has(id));
  return id;
}

/* Seed data (first visit only). Every demo account signs in with the
   password "Calmio123" - full list in the README. Delete before real use. */
const DEMO_PASS = "Calmio123";
async function seed() {
  if (DB.read("calmio_users", null)) return;
  const acc = async (name, email, display, role, extra = {}) => {
    const salt = newSalt();
    return { id: uid(), name, email, display, role, salt,
             passHash: await makeHash(DEMO_PASS, salt), profile: {}, ...extra };
  };
  const t1 = await acc("dr.lori",     "lori@hanoihigh.edu.vn",    "Dr. Lori",     "teacher");
  const t2 = await acc("mr.hart",     "hart@hanoihigh.edu.vn",    "Mr. Hart",     "teacher");
  const t3 = await acc("mrs.speidel", "speidel@hanoihigh.edu.vn", "Mrs. Speidel", "teacher");
  const a1 = await acc("admin",       "admin@hanoihigh.edu.vn",   "School Administrator", "admin");
  DB.write("calmio_users", [t1, t2, t3]);
  DB.write("calmio_articles", [
    { id: uid(), title: "What to do when a friend is dealing with anxiety?",
      url: "https://www.nimh.nih.gov/health/topics/anxiety-disorders",
      keywords: "Anxiety, Friendship", minutes: 2, byName: t3.name, ts: now() - 864e5 },
    { id: uid(), title: "How to do box-breathing techniques?",
      url: "https://www.youtube.com/watch?v=tEmt1Znux58",
      keywords: "Anxiety, Stress, Life Skills", minutes: 2, byName: t1.name, ts: now() - 2 * 864e5 },
    { id: uid(), title: "How to deal with anxiety during a game?",
      url: "https://www.apa.org/topics/anxiety",
      keywords: "Sports, Pressure", minutes: 5, byName: t3.name, ts: now() - 7 * 864e5 }
  ]);
  /* ----- Synthetic demo students (so the Students tab has something to show).
         Delete this block before real use. ----- */
  const D = 864e5;                       // one day in ms
  const mk = async (username, display, profile) =>
    acc(username, username.replace(/[^a-z0-9.]/g, "") + "@hanoihigh.edu.vn", display, "student",
        { profile, school: "Hanoi High", anonId: newAnonId() });
  const s1 = await mk("minhanh.nguyen", "Minh Anh", { fullName: "Nguyen Minh Anh", nickname: "Mia", school: "Hanoi High", className: "11A2", hobbies: "Piano, reading", clubs: "Media club" });
  const s2 = await mk("duc.tran",       "Duc",      { fullName: "Tran Duc",        nickname: "",    school: "Hanoi High", className: "10B1", hobbies: "Football",       clubs: "Football team" });
  const s3 = await mk("lan.pham",       "Lan",      { fullName: "Pham Lan",        nickname: "",    school: "Hanoi High", className: "12C3", hobbies: "Drawing",        clubs: "Art club" });
  const s4 = await mk("khoa.le",        "Khoa",     { fullName: "Le Khoa",         nickname: "",    school: "Hanoi High", className: "11A2", hobbies: "Chess, coding",  clubs: "STEM club" });
  const s5 = await mk("thu.vu",         "Thu",      { fullName: "Vu Thu",          nickname: "",    school: "Hanoi High", className: "10B2", hobbies: "Badminton",      clubs: "Charity run team" });
  const s6 = await mk("bao.ngo",        "Bao",      { fullName: "Ngo Bao",         nickname: "",    school: "Hanoi High", className: "12A1", hobbies: "Guitar, running",clubs: "Music club" });
  const s7 = await mk("hana.dang",      "Hana",     { fullName: "Dang Hana",       nickname: "Han", school: "Hanoi High", className: "11C1", hobbies: "Volleyball",     clubs: "Student council" });
  const s8 = await mk("tuan.bui",       "Tuan",     { fullName: "Bui Tuan",        nickname: "",    school: "Hanoi High", className: "10A3", hobbies: "Gaming",         clubs: "" });
  const s9 = await mk("linh.hoang",     "Linh",     { fullName: "Hoang Linh",      nickname: "",    school: "Hanoi High", className: "12B2", hobbies: "Photography",    clubs: "Yearbook team" });
  DB.write("calmio_users", [t1, t2, t3, a1, s1, s2, s3, s4, s5, s6, s7, s8, s9]);

  const th = (from, daysAgo, body, mood, opts = {}) => ({
    id: uid(), fromId: from.id, fromName: disp(from), toId: "all",
    anonymous: !!opts.anon, urgent: !!opts.urgent, body,
    ts: now() - daysAgo * D, replies: opts.replies || [],
    mood, risk: !!opts.risk
  });
  const rep = (t, daysAgo, body) => ({ fromId: t.id, name: t.display, body, ts: now() - daysAgo * D });

  DB.write("calmio_thoughts", [
    // Minh Anh - started low with exam stress, clearly improving
    th(s1, 24, "I have two exams in one day next week and I can't sleep properly. My mind keeps racing at night.", 32,
       { replies: [rep(t1, 23.6, "That sounds exhausting. Racing thoughts before exams are very common - want to drop by after class and we'll make a revision plan together?")] }),
    th(s1, 16, "We made the plan and I tried the box-breathing video before studying. Still nervous but I slept better this week.", 55,
       { replies: [rep(t1, 15.7, "That's real progress, Mia. Keep the breathing before study sessions and be kind to yourself on the busy days.")] }),
    th(s1, 6,  "Exams went okay! I actually felt calm walking in. Thank you for the plan, it really helped.", 82,
       { replies: [rep(t1, 5.8, "So glad to hear it. You did the work - the plan just held the door open. Come by any time.")] }),

    // Duc - steady, one dip after a match
    th(s2, 12, "We lost the semifinal and I feel like I let the whole team down. Everyone says it's fine but it doesn't feel fine.", 41,
       { replies: [rep(t2, 11.7, "One match never belongs to one player. Losses sting because you care - that's not a flaw. Let's talk before Friday practice.")] }),
    th(s2, 4,  "Talked with the coach like you suggested. He showed me what I did well in the second half. Feeling more like myself.", 68),

    // Lan - anonymous student, declining trend the AI flags for counseling
    th(s3, 20, "Lately I just feel tired of everything. School, home, all of it.", 38, { anon: true }),
    th(s3, 10, "It's getting harder to care about classes. I sit in the back and the day just passes through me.", 30, { anon: true,
       replies: [rep(t3, 9.6, "Thank you for trusting us with this, even anonymously. What you're describing deserves real support. I'm here every day at lunch, room 204 - no appointment needed.")] }),
    th(s3, 3,  "I feel bad today. Everything feels heavy and I don't really see the point of trying anymore.", 18, { anon: true, risk: true }),

    // Khoa - friendship trouble, stable-low but improving slightly
    th(s4, 15, "My best friend has been ignoring me since I joined the chess team. I don't know what I did wrong.", 44,
       { replies: [rep(t2, 14.5, "Friendships shifting is painful and confusing. Before assuming you did something wrong, would you feel okay asking him directly? We can practice how.")] }),
    th(s4, 5,  "I asked him. He felt left out, not angry. We're okay now, just needed to say it out loud I guess.", 71),

    // Thu - new student, homesick, only one message so far
    th(s5, 2,  "I just transferred here and I don't know anyone yet. Lunch is the loneliest hour of my day.", 45),

    // Bao - doing well, checks in positively (high, stable)
    th(s6, 14, "Not a problem exactly - I just wanted to say the exam-week articles helped a lot. Feeling on top of things.", 84),
    th(s6, 3,  "Got into the district music showcase! Practicing every day and honestly loving it.", 90),

    // Hana - up and down: council pressure swings her week to week
    th(s7, 21, "Student council is a lot. I love it but this week I cried in the bathroom after the budget meeting.", 36,
       { replies: [rep(t3, 20.6, "Caring that much is a strength, but it shouldn't cost you your lunch breaks and sleep. Can we look at what's delegable?")] }),
    th(s7, 13, "Delegated the fundraiser like we discussed. Slept properly for the first time in weeks. Maybe I can do this.", 66),
    th(s7, 8,  "Two council members quit and it all landed back on me. I feel like I'm drowning in it again.", 33),
    th(s7, 1,  "The teachers stepped in to help recruit. It's manageable this week. Up and down, I guess that's how it goes.", 58),

    // Tuan - was in real trouble months ago, long recovery arc (crisis -> steady)
    th(s8, 45, "I failed three subjects and my parents shout every night. I've been staying up until 4am gaming to not think about it.", 22,
       { replies: [rep(t2, 44.5, "That sounds like a really heavy place to be, and numbing out until 4am makes school feel even harder the next day. Come see me tomorrow - we'll take it one subject at a time, and I can help with the conversation at home too.")] }),
    th(s8, 33, "Met with you and my parents. Still tense at home but at least nobody is shouting about grades this week.", 40),
    th(s8, 19, "Passed the maths retake. Sleeping before midnight most days now. Games only on weekends, mostly.", 57),
    th(s8, 7,  "Honestly okay lately. Dad even asked about my ranked matches instead of my ranks at school. Weird but nice.", 74,
       { replies: [rep(t2, 6.8, "That made me smile. You rebuilt this yourself, one week at a time - remember that next time things wobble.")] }),

    // Linh - flat and guarded: short neutral notes, hard to read
    th(s9, 9,  "Fine I guess. Yearbook deadlines. Nothing to report.", 50),
    th(s9, 2,  "Still fine. Busy. Do these messages actually go anywhere?", 48,
       { replies: [rep(t1, 1.8, "They do - a real person reads every one, and I just did. Deadlines season is real; my door is open if 'fine' ever stops being the whole story.")] })
  ]);

  DB.write("calmio_loves", []);
  DB.write("calmio_slots", []);
  DB.write("calmio_testimonials", []);
  DB.write("calmio_feedback", []);
  DB.write("calmio_reports", []);
  DB.write("calmio_notes", {
    ["user:" + s1.id]: [
      { id: uid(), byName: t1.name, text: "Met after class - built a two-week revision plan, introduced box breathing. Check in after exams.", ts: now() - 23 * D },
      { id: uid(), byName: t1.name, text: "Exams done, mood visibly brighter. Moving to monthly light check-ins.", ts: now() - 5 * D }
    ],
    ["anon:" + s3.id]: [
      { id: uid(), byName: t3.name, text: "Anonymous student, three messages with a downward trend. Latest message flagged by the AI - keeping lunch hours open and will gently invite again in my next reply.", ts: now() - 3 * D }
    ],
    ["user:" + s4.id]: [
      { id: uid(), byName: t2.name, text: "Role-played the conversation with his friend. He followed through and it resolved well.", ts: now() - 4 * D }
    ],
    ["user:" + s7.id]: [
      { id: uid(), byName: t3.name, text: "Pattern: overload -> delegate -> relief -> overload again. Working with her on saying no earlier, and asked the council advisor to watch her workload.", ts: now() - 7 * D }
    ],
    ["user:" + s8.id]: [
      { id: uid(), byName: t2.name, text: "Family meeting held, weekly subject plan agreed. Parents on board with grades-off dinners.", ts: now() - 32 * D },
      { id: uid(), byName: t2.name, text: "Six weeks steady improvement. Moving from weekly to fortnightly check-ins.", ts: now() - 6 * D }
    ],
    ["user:" + s9.id]: [
      { id: uid(), byName: t1.name, text: "Guarded, minimal messages, mood readings hover at neutral. Not pushing - keeping a light, reliable presence so the door stays open.", ts: now() - 1.5 * D }
    ]
  });
}

/* One-time upgrades for data created by earlier versions */
function migrateData() {
  const users = DB.read("calmio_users", []);
  let changed = false;
  for (const u of users) {
    if (u.role === "student" && !u.anonId) { u.anonId = newAnonId(); changed = true; }
    if (!u.display) { u.display = u.name; changed = true; }
    if (u.email === undefined) { u.email = ""; changed = true; }
  }
  if (changed) DB.write("calmio_users", users);

  const thoughts = DB.read("calmio_thoughts", []);
  let tChanged = false;
  for (const t of thoughts) {
    if (t.mood === undefined) { const ev = evaluateMood(t.body); t.mood = ev.score; t.risk = ev.risk; tChanged = true; }
  }
  if (tChanged) DB.write("calmio_thoughts", thoughts);
}

/* School settings (set by administrators) */
const DEFAULT_CRISIS_LINES = [
  { label: "111 - National Child Helpline", sub: "Free, 24/7, for children and teenagers", number: "111" },
  { label: "115 - Medical emergency", sub: "Ambulance and urgent medical help", number: "115" },
  { label: "113 - Police", sub: "If someone's safety is at risk right now", number: "113" }
];
function getSettings() {
  const s = DB.read("calmio_settings", {
    counselorName: "", counselorOffice: "", counselorPhone: "",
    hoursStart: 8, hoursEnd: 16
  });
  if (!Array.isArray(s.crisisLines) || !s.crisisLines.length) s.crisisLines = DEFAULT_CRISIS_LINES;
  return s;
}
function crisisLinesHTML() {
  return getSettings().crisisLines.map(l => `
    <div class="crisis-line">
      <div><b>${esc(l.label)}</b>${l.sub ? `<br /><span class="tiny">${esc(l.sub)}</span>` : ""}</div>
      <a class="call-btn" href="tel:${esc(l.number)}">Call ${esc(l.number)}</a>
    </div>`).join("");
}

function isSchoolHours() {
  const s = getSettings();
  const d = new Date();
  const day = d.getDay();               // 0 Sun ... 6 Sat
  const hour = d.getHours() + d.getMinutes() / 60;
  return day >= 1 && day <= 5 && hour >= s.hoursStart && hour < s.hoursEnd;
}

/* Counselor line HTML, or "" if not configured / outside school hours */
function counselorLine() {
  const s = getSettings();
  if (!s.counselorPhone || !isSchoolHours()) return "";
  const who = s.counselorName ? esc(s.counselorName) : "School Counselor";
  const where = s.counselorOffice ? `<br /><span class="tiny">Walk in: ${esc(s.counselorOffice)} - open right now</span>` : "";
  return `<div class="crisis-line">
    <div><b>${who}</b> (your school counselor)${where}</div>
    <a class="call-btn" href="tel:${esc(s.counselorPhone.replace(/[^\d+]/g, ""))}">Call ${esc(s.counselorPhone)}</a>
  </div>`;
}

/* ---------- Message scanning ----------
   Pattern-based check for language about harming oneself or others.
   For production, replace with a fetch() to your own serverless
   endpoint that asks a real AI model (see README - the API key must
   live on the server, never here). */
const RISK_PATTERNS = [
  /kill (myself|him|her|them|someone)/i,
  /suicid/i,
  /self.?harm/i,
  /hurt (myself|him|her|them|someone|others)/i,
  /end (it all|my life)/i,
  /(want|wanted|going) to die/i,
  /don'?t want to (live|be here|exist)/i,
  /better off without me/i,
  /no (reason|point) (to|in) (live|living|going on)/i,
  /cutting myself/i,
  /harm (myself|someone|others)/i
];

function scanForRisk(text) {
  return RISK_PATTERNS.some(re => re.test(text));
}

/* ---------- AI mood evaluation (demo, rule-based) ----------
   Scores a message 0-100 (higher = doing better) and decides whether
   counseling looks needed. A real deployment should replace this with
   a server-side call to an AI model - same shape of result. */
const MOOD_NEG = [
  "sad", "anxious", "anxiety", "stress", "stressed", "panic", "cry", "crying",
  "scared", "afraid", "tired", "exhausted", "lonely", "alone", "hopeless",
  "overwhelmed", "angry", "hurt", "fail", "failed", "failing", "worthless",
  "hate", "worried", "worry", "depressed", "depressing", "pressure", "bad",
  "terrible", "awful", "nervous", "can't sleep", "cant sleep", "give up",
  "buồn", "lo lắng", "áp lực", "mệt", "cô đơn", "sợ", "chán", "khóc", "tuyệt vọng"
];
const MOOD_POS = [
  "happy", "better", "great", "good", "excited", "proud", "calm", "relieved",
  "thankful", "grateful", "hopeful", "improving", "improved", "fun", "enjoy",
  "enjoyed", "love", "passed", "won", "confident", "okay now", "fine now",
  "vui", "tốt hơn", "hạnh phúc", "tự hào", "bình tĩnh", "ổn"
];

function evaluateMood(text) {
  const t = (text || "").toLowerCase();
  let score = 60;
  for (const w of MOOD_NEG) if (t.includes(w)) score -= 9;
  for (const w of MOOD_POS) if (t.includes(w)) score += 8;
  const risk = scanForRisk(text);
  if (risk) score = Math.min(score, 15);
  score = Math.max(5, Math.min(95, score));
  return { score, risk };
}

function moodBand(score, risk) {
  if (risk)        return { label: "At risk - act today and involve your crisis team", cls: "mood-risk" };
  if (score <= 30) return { label: "Struggling - counseling strongly recommended",     cls: "mood-risk" };
  if (score <= 50) return { label: "Having a hard time - counseling recommended",      cls: "mood-low" };
  if (score <= 68) return { label: "Mixed - keep an eye on them",                      cls: "mood-mid" };
  return             { label: "Doing well",                                            cls: "mood-good" };
}

/* ---------- Testimonial quality gate ----------
   Only 5-star reviews with clearly kind wording (and explicit
   permission) ever appear in "People we have helped". */
const NEGATIVE_WORDS = [
  // English
  "bad", "terrible", "awful", "hate", "hated", "worst", "useless", "scam",
  "waste", "horrible", "sucks", "sucked", "poor", "disappointing",
  "disappointed", "broken", "creepy", "unsafe", "annoying", "boring",
  "stupid", "trash", "garbage",
  // Vietnamese
  "tệ", "chán", "ghét", "dở", "kém", "vô dụng", "lừa đảo", "xấu",
  "thất vọng", "phí", "rác"
];
function isKindMessage(msg) {
  const m = (msg || "").toLowerCase();
  if (m.trim().length < 15) return false;                 // too short to mean much
  return !NEGATIVE_WORDS.some(w => m.includes(w));
}

/* ---------- Small SVG helpers (no emoji, no symbol characters) ---------- */
function starSvg(size) {
  return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="currentColor" aria-hidden="true"><path d="M12 2.6l2.8 6 6.5.8-4.8 4.5 1.3 6.5L12 17.2l-5.8 3.2 1.3-6.5L2.7 9.4l6.5-.8z"/></svg>`;
}
function starsRow(n) {
  return `<span class="stars-static">${starSvg(15).repeat(n)}</span>`;
}

/* ---------- Google Calendar link builder ---------- */
function gcalLink(title, startMs, minutes, details) {
  const fmt = ms => new Date(ms).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const dates = fmt(startMs) + "/" + fmt(startMs + minutes * 60000);
  return "https://calendar.google.com/calendar/render?action=TEMPLATE"
    + "&text=" + encodeURIComponent(title)
    + "&dates=" + dates
    + "&details=" + encodeURIComponent(details);
}
function fmtSlot(startMs, minutes) {
  const d = new Date(startMs);
  const day = d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
  const time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return `${day}, ${time} (${minutes} min)`;
}

/* ---------- Week helpers for the booking calendar ---------- */
function startOfWeek(offsetWeeks) {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  const day = (d.getDay() + 6) % 7;         // 0 = Monday
  d.setDate(d.getDate() - day + offsetWeeks * 7);
  return d;
}
const BOOK_CUTOFF_MS = 30 * 60000;          // bookable until 30 min before start

/* ============================ App ============================ */
const app = {
  me: null,
  pendingRole: "student",
  openThoughtId: null,
  deleteDraft: { rating: 0 },
  locked: false,
  _lastActivity: now(),
  weekOffset: 0,
  studentKeys: [],       // ordered identity keys for the Students tab
  studentIdx: 0,
  studentQuery: "",
  _convoFrom: null,      // where the convo view was opened from

  async init() {
    if (Remote.configure()) {
      // Multi-user mode: Supabase is the source of truth. Sessions live in
      // sessionStorage (closing the tab signs you out), restored here.
      await Remote.init();
      if (Remote.session) {
        await Remote.loadAll();
        this.me = Remote.me();
      }
    } else {
      await seed();
      migrateData();
      // The session lives in sessionStorage only: closing the page/tab wipes it,
      // so reopening Calmio always asks you to sign in again.
      const sessionId = sessionStorage.getItem("calmio_session");
      if (sessionId) {
        this.me = DB.read("calmio_users", []).find(u => u.id === sessionId) || null;
      }
      DB.remove("calmio_session");               // clear sessions left behind by older versions
      try { localStorage.removeItem("calmio_session"); } catch {}
    }
    if (this.me) { this.enter(); } else { this.show("welcome"); }
    this.renderTestimonials();
    this.watchActivity();
    // Build the star-rating buttons for the delete flow
    const stars = document.getElementById("del-stars");
    stars.innerHTML = [1, 2, 3, 4, 5].map(n =>
      `<button type="button" onclick="app.setStars(${n})" aria-label="${n} star${n > 1 ? "s" : ""}">${starSvg(22)}</button>`).join("");
  },

  /* ---------- security: auto-lock ---------- */
  lockMinutes() { return (this.me && this.me.lockMinutes) || 10; },

  watchActivity() {
    const bump = () => { this._lastActivity = now(); };
    ["pointerdown", "keydown", "scroll", "touchstart"].forEach(ev =>
      window.addEventListener(ev, bump, { passive: true }));
    setInterval(() => {
      if (this.me && !this.locked &&
          now() - this._lastActivity > this.lockMinutes() * 60000) {
        this.lockNow();
      }
    }, 5000);
  },

  lockNow() {
    if (!this.me) return;
    this.locked = true;
    document.getElementById("lock-pass").value = "";
    document.getElementById("lock-msg").textContent = "";
    document.getElementById("lockscreen").classList.add("open");
    document.getElementById("lock-pass").focus();
  },

  async unlock() {
    const pass = document.getElementById("lock-pass").value;
    const msg = document.getElementById("lock-msg");
    if (!this.me) { this.logoutFromLock(); return; }
    const res = Remote.on ? { ok: await Remote.reauth(pass) } : await verifyPass(this.me, pass);
    if (res.ok) {
      if (res.upgraded) this.saveMe();
      this.locked = false;
      this._lastActivity = now();
      document.getElementById("lockscreen").classList.remove("open");
    } else {
      msg.textContent = "That password doesn't match. Try again.";
    }
  },

  logoutFromLock() {
    document.getElementById("lockscreen").classList.remove("open");
    this.locked = false;
    this.logout();
  },

  /* ---------- auth ---------- */
  authTab(which) {
    document.getElementById("login-form").hidden = which !== "login";
    document.getElementById("signup-form").hidden = which !== "signup";
    document.getElementById("lockout-msg").textContent = "";
    document.getElementById("signup-msg").textContent = "";
  },

  suggestSchool() {
    const field = document.getElementById("su-school");
    const guess = schoolFromEmail(document.getElementById("su-email").value);
    if (guess && (!field.value.trim() || field.dataset.auto === "1")) {
      field.value = guess;
      field.dataset.auto = "1";
    }
  },

  /* Sign in with username OR email + password. Accounts are never created here. */
  async login() {
    const idRaw = document.getElementById("login-id").value.trim();
    const pass = document.getElementById("login-pass").value;
    const msg = document.getElementById("lockout-msg");
    msg.textContent = "";
    if (!idRaw || !pass) { msg.textContent = "Enter your username or email and your password."; return; }

    if (Remote.on) {
      msg.textContent = "Signing in...";
      const res = await Remote.signIn(idRaw, pass);
      if (res.error) { msg.textContent = res.error; return; }
      await Remote.loadAll();
      this.me = Remote.me();
      if (!this.me) { msg.textContent = "Signed in, but no profile was found. Ask your administrator."; return; }
      msg.textContent = "";
      document.getElementById("login-pass").value = "";
      this.enter();
      return;
    }

    const lock = getLockout(idRaw);
    if (lock.until > now()) {
      const secs = Math.ceil((lock.until - now()) / 1000);
      msg.textContent = `Too many wrong attempts. Sign-in is paused for ${secs} more seconds.`;
      return;
    }

    const idLow = idRaw.toLowerCase();
    const users = DB.read("calmio_users", []);
    const user = users.find(u =>
      u.name.toLowerCase() === idLow || (u.email && u.email.toLowerCase() === idLow));

    if (!user || !user.passHash) {
      // Same message whether the account or the password is wrong,
      // so the sign-in form can't be used to probe which usernames exist.
      this._loginFail(idRaw, lock, msg);
      return;
    }
    const res = await verifyPass(user, pass);
    if (!res.ok) { this._loginFail(idRaw, lock, msg); return; }
    if (res.upgraded) DB.write("calmio_users", users);
    setLockout(idRaw, { fails: 0, until: 0 });

    document.getElementById("login-pass").value = "";
    this.me = user;
    sessionStorage.setItem("calmio_session", user.id);
    this.enter();
  },

  _loginFail(id, lock, msg) {
    const fails = lock.fails + 1;
    if (fails >= LOCK_MAX_FAILS) {
      setLockout(id, { fails: 0, until: now() + LOCK_SECONDS * 1000 });
      msg.textContent = `Wrong sign-in details ${LOCK_MAX_FAILS} times - paused for ${LOCK_SECONDS} seconds.`;
    } else {
      setLockout(id, { fails, until: 0 });
      msg.textContent = `That username/email and password don't match (attempt ${fails} of ${LOCK_MAX_FAILS}).`;
    }
  },

  /* Shared checks for any new account (public sign-up and admin-created) */
  validateNewUser({ username, email, fullname, pass, pass2 }) {
    if (!USERNAME_RE.test(username))
      return "Usernames are 3-20 characters: lowercase letters, numbers, dots, dashes or underscores, starting with a letter or number.";
    if (!EMAIL_RE.test(email)) return "That doesn't look like a valid email address.";
    if (!fullname) return "Please enter a full name.";
    if (pass.length < 6) return "Passwords need at least 6 characters.";
    if (pass2 !== undefined && pass !== pass2) return "The two passwords don't match.";
    if (!Remote.on) {
      const users = DB.read("calmio_users", []);
      if (users.some(u => u.name.toLowerCase() === username)) return "That username is already taken - try another.";
      if (users.some(u => u.email && u.email.toLowerCase() === email)) return "An account with that email already exists. Try signing in instead.";
    }
    return null;
  },

  /* Public sign-up: creates STUDENT accounts only. */
  async register() {
    const msg = document.getElementById("signup-msg");
    msg.textContent = "";
    const username = document.getElementById("su-username").value.trim().toLowerCase();
    const email = document.getElementById("su-email").value.trim().toLowerCase();
    const fullname = document.getElementById("su-fullname").value.trim();
    const school = document.getElementById("su-school").value.trim();
    const pass = document.getElementById("su-pass").value;
    const pass2 = document.getElementById("su-pass2").value;
    if (!school) { msg.textContent = "Please enter your school."; return; }
    if (!document.getElementById("su-agree").checked) { msg.textContent = "Please read and tick the privacy box first."; return; }
    const err = this.validateNewUser({ username, email, fullname, pass, pass2 });
    if (err) { msg.textContent = err; return; }

    if (Remote.on) {
      msg.textContent = "Creating your account...";
      const res = await Remote.signUp({ username, email, fullname, school, password: pass });
      if (res.error) { msg.textContent = res.error; return; }
      if (res.confirm) {
        msg.style.color = "var(--cacao)";
        msg.textContent = "Almost there - check your email and click the confirmation link, then sign in.";
        return;
      }
      await Remote.loadAll();
      // Save the profile bits the sign-up trigger doesn't know about
      const users = DB.read("calmio_users", []);
      const mine = users.find(u => u.id === Remote.uid());
      if (mine) {
        mine.profile = { ...(mine.profile || {}), fullName: fullname, school };
        DB.write("calmio_users", users);
      }
      this.me = Remote.me();
      this.toast("Account created. Welcome to Calmio.");
      this.enter();
      return;
    }

    const salt = newSalt();
    const user = {
      id: uid(), name: username, email, display: fullname, role: "student",
      salt, passHash: await makeHash(pass, salt),
      profile: { fullName: fullname, school }, school,
      lockMinutes: 10, anonId: newAnonId()
    };
    const users = DB.read("calmio_users", []);
    users.push(user);
    DB.write("calmio_users", users);

    this.me = user;
    sessionStorage.setItem("calmio_session", user.id);
    this.toast("Account created. Welcome to Calmio.");
    this.enter();
  },

  logout() {
    if (Remote.on) Remote.signOut();
    sessionStorage.removeItem("calmio_session");
    this.me = null;
    document.getElementById("topbar").hidden = true;
    this.authTab("login");
    document.getElementById("login-pass").value = "";
    this.show("welcome");
    this.renderTestimonials();
  },

  enter() {
    document.getElementById("topbar").hidden = false;
    this.renderAvatar();
    document.getElementById("whoami-name").textContent = disp(this.me) + " \u00b7 " + (this.me.role === "teacher" ? "counselor" : this.me.role);
    this._lastActivity = now();
    this.buildNav();
    this.backHome();
    this.creditWater("login");
    if (Remote.on) Remote.startPolling(() => {
      this.me = Remote.me() || this.me;
      if (this._view && this._view !== "welcome") this.show(this._view);
    });
  },

  renderAvatar() {
    const el = document.getElementById("avatar");
    const p = this.me.profile || {};
    el.innerHTML = p.photo
      ? `<img src="${p.photo}" alt="" />`
      : esc(disp(this.me).trim()[0].toUpperCase());
  },

  buildNav() {
    const nav = document.getElementById("mainnav");
    const links = this.me.role === "student"
      ? [["Home", "student-home"], ["Share", "share"], ["Schedule", "schedule"], ["Garden", "garden"], ["Articles", "articles"]]
      : this.me.role === "teacher"
      ? [["Home", "teacher-home"], ["Students", "students"], ["Share love", "share"], ["Articles", "articles"], ["AI Helper", "ai"]]
      : [["School settings", "admin-home"], ["Articles", "articles"]];
    nav.innerHTML = "";
    for (const [label, view] of links) {
      const b = document.createElement("button");
      b.textContent = label;
      b.dataset.view = view;
      b.onclick = () => this.show(view);
      nav.appendChild(b);
    }
  },

  /* ---------- navigation ---------- */
  show(view) {
    this._view = view;
    document.querySelectorAll(".view").forEach(v => v.classList.remove("visible"));
    document.getElementById("view-" + view).classList.add("visible");
    document.querySelectorAll("#mainnav button").forEach(b =>
      b.classList.toggle("active", b.dataset.view === view));
    if (view === "student-home") this.renderStudentHome();
    if (view === "teacher-home") this.renderTeacherHome();
    if (view === "admin-home")   this.renderAdminHome();
    if (view === "share")        this.renderShare();
    if (view === "articles")     this.renderArticles();
    if (view === "emergency")    this.renderEmergency();
    if (view === "schedule")     this.renderSchedule();
    if (view === "account")      this.renderAccount();
    if (view === "students")     this.renderStudents();
    if (view === "garden")       this.renderGarden();
    if (view === "welcome")      this.renderTestimonials();
    window.scrollTo(0, 0);
  },

  backHome() {
    const home = { student: "student-home", teacher: "teacher-home", admin: "admin-home" };
    this.show(home[this.me.role] || "student-home");
  },

  /* ---------- admin ---------- */
  renderAdminHome() {
    const s = getSettings();
    document.getElementById("set-counselor-name").value = s.counselorName;
    document.getElementById("set-counselor-office").value = s.counselorOffice;
    document.getElementById("set-counselor-phone").value = s.counselorPhone;
    document.getElementById("set-hours-start").value = s.hoursStart;
    document.getElementById("set-hours-end").value = s.hoursEnd;
    this._crisisDraft = s.crisisLines.map(l => ({ ...l }));
    this.renderCrisisEditor();
    this.renderTeamList();
    this.renderReports();
  },

  renderCrisisEditor() {
    document.getElementById("crisis-editor").innerHTML = this._crisisDraft.map((l, i) => `
      <div class="crisis-edit-row">
        <input type="text" value="${esc(l.label)}" placeholder="Name of the line"
               oninput="app._crisisDraft[${i}].label=this.value" />
        <input type="text" value="${esc(l.sub || "")}" placeholder="Short note (hours, who it's for)"
               oninput="app._crisisDraft[${i}].sub=this.value" />
        <input type="text" value="${esc(l.number)}" placeholder="Phone number" class="crisis-num"
               oninput="app._crisisDraft[${i}].number=this.value" />
        <button class="linklike" onclick="app.removeCrisisLine(${i})">Remove</button>
      </div>`).join("");
  },
  addCrisisLine() {
    this._crisisDraft.push({ label: "", sub: "", number: "" });
    this.renderCrisisEditor();
  },
  removeCrisisLine(i) {
    this._crisisDraft.splice(i, 1);
    this.renderCrisisEditor();
  },
  saveCrisisLines() {
    const lines = this._crisisDraft
      .map(l => ({ label: l.label.trim(), sub: (l.sub || "").trim(), number: l.number.trim() }))
      .filter(l => l.label && l.number);
    if (!lines.length) { this.toast("Keep at least one crisis line - students rely on this page."); return; }
    const s = getSettings();
    s.crisisLines = lines;
    DB.write("calmio_settings", s);
    this._crisisDraft = lines.map(l => ({ ...l }));
    this.renderCrisisEditor();
    this.toast("Crisis lines saved.");
  },

  async createTeamAccount() {
    const username = document.getElementById("ta-username").value.trim().toLowerCase();
    const email = document.getElementById("ta-email").value.trim().toLowerCase();
    const fullname = document.getElementById("ta-fullname").value.trim();
    const role = document.getElementById("ta-role").value;
    const pass = document.getElementById("ta-pass").value;
    const err = this.validateNewUser({ username, email, fullname, pass });
    if (err) { this.toast(err); return; }
    if (Remote.on) {
      this.toast("Creating the account...");
      const res = await Remote.staff({ action: "create", username, email, fullname, role, password: pass });
      if (res.error) { this.toast(res.error); return; }
      await Remote.loadAll();
      ["ta-username", "ta-email", "ta-fullname", "ta-pass"].forEach(i => document.getElementById(i).value = "");
      this.renderTeamList();
      this.toast(`${role === "admin" ? "Administrator" : "Counselor"} account created. Share the sign-in details privately.`);
      return;
    }
    const salt = newSalt();
    const users = DB.read("calmio_users", []);
    users.push({
      id: uid(), name: username, email, display: fullname, role,
      salt, passHash: await makeHash(pass, salt),
      profile: { fullName: fullname }, lockMinutes: 10
    });
    DB.write("calmio_users", users);
    ["ta-username", "ta-email", "ta-fullname", "ta-pass"].forEach(i => document.getElementById(i).value = "");
    this.renderTeamList();
    this.toast(`${role === "admin" ? "Administrator" : "Counselor"} account created. Share the sign-in details privately.`);
  },

  renderTeamList() {
    const team = DB.read("calmio_users", []).filter(u => u.role !== "student");
    document.getElementById("team-list").innerHTML = team.map(u => `
      <div class="list-item">
        <b>${esc(disp(u))}</b> <span class="pill">${u.role === "teacher" ? "counselor" : "admin"}</span>
        <div class="tiny">${esc(u.name)}${u.email ? " \u00b7 " + esc(u.email) : ""}</div>
        ${u.id !== this.me.id ? `<button class="linklike" onclick="app.removeTeamAccount('${u.id}')">Remove account</button>` : `<span class="tiny">(you)</span>`}
      </div>`).join("");
  },

  async removeTeamAccount(id) {
    const u = DB.read("calmio_users", []).find(x => x.id === id);
    if (!u || u.id === this.me.id) return;
    if (!confirm(`Remove the account "${disp(u)}"? Their availability and published articles stay; they just can't sign in anymore.`)) return;
    if (Remote.on) {
      const res = await Remote.staff({ action: "remove", target: id });
      if (res.error) { this.toast(res.error); return; }
      await Remote.loadAll();
      this.renderTeamList();
      this.toast("Account removed.");
      return;
    }
    DB.write("calmio_users", DB.read("calmio_users", []).filter(x => x.id !== id));
    this.renderTeamList();
    this.toast("Account removed.");
  },

  saveSettings() {
    const start = parseFloat(document.getElementById("set-hours-start").value);
    const end = parseFloat(document.getElementById("set-hours-end").value);
    DB.write("calmio_settings", {
      counselorName: document.getElementById("set-counselor-name").value.trim(),
      counselorOffice: document.getElementById("set-counselor-office").value.trim(),
      counselorPhone: document.getElementById("set-counselor-phone").value.trim(),
      hoursStart: isNaN(start) ? 8 : start,
      hoursEnd: isNaN(end) ? 16 : end
    });
    this.toast("Settings saved. The booking calendar and counselor line follow these hours.");
  },

  /* ---------- privacy policy (footer link) ---------- */
  openPrivacy()  { document.getElementById("privacy-backdrop").classList.add("open"); },
  closePrivacy() { document.getElementById("privacy-backdrop").classList.remove("open"); },

  /* ---------- report a problem (bottom-right button, goes to the admin) ---------- */
  openReport() {
    document.getElementById("report-body").value = "";
    document.getElementById("report-backdrop").classList.add("open");
    document.getElementById("report-body").focus();
  },
  closeReport() { document.getElementById("report-backdrop").classList.remove("open"); },

  sendReport() {
    const body = document.getElementById("report-body").value.trim();
    if (!body) { this.toast("Describe the problem first."); return; }
    const reports = DB.read("calmio_reports", []);
    reports.push({
      id: uid(),
      byName: this.me ? `${disp(this.me)} (${this.me.role})` : "Not signed in",
      body, ts: now()
    });
    DB.write("calmio_reports", reports);
    this.closeReport();
    this.toast("Thank you - your report was sent to the administrator.");
  },

  renderReports() {
    const el = document.getElementById("admin-reports");
    const reports = DB.read("calmio_reports", []).sort((a, b) => b.ts - a.ts);
    el.innerHTML = reports.length
      ? reports.map(r => `
          <div class="note-item">
            <div>${esc(r.body)}</div>
            <span class="tiny">${esc(r.byName)} \u00b7 ${timeAgo(r.ts)}</span>
            <button class="linklike" onclick="app.dismissReport('${r.id}')">Mark as resolved</button>
          </div>`).join("")
      : `<p class="muted">No open reports. Anything users send appears here.</p>`;
  },

  dismissReport(id) {
    DB.write("calmio_reports", DB.read("calmio_reports", []).filter(r => r.id !== id));
    this.renderReports();
    this.toast("Report resolved.");
  },

  toast(msg) {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(this._toastTimer);
    this._toastTimer = setTimeout(() => t.classList.remove("show"), 2600);
  },

  teachers() { return DB.read("calmio_users", []).filter(u => u.role === "teacher"); },
  saveMe() {
    const users = DB.read("calmio_users", []);
    const i = users.findIndex(u => u.id === this.me.id);
    if (i >= 0) { users[i] = this.me; DB.write("calmio_users", users); }
  },

  /* ---------- student home ---------- */
  renderStudentHome() {
    this.renderTestimonials();
    const p = this.me.profile || {};
    document.getElementById("student-greeting").textContent =
      "How's it going, " + (p.nickname || disp(this.me)) + "?";

    // Loves received
    const loves = DB.read("calmio_loves", []).filter(l => l.toId === this.me.id).sort((a, b) => b.ts - a.ts);
    document.getElementById("student-loves").innerHTML = loves.length
      ? loves.slice(0, 5).map(l =>
          `<div class="notice"><b>${esc(l.fromName)}</b> just sent you a <b>love</b> for your <i>${esc(l.reason)}</i>! <span class="tiny">${timeAgo(l.ts)}</span></div>`).join("")
      : `<p class="muted">Nothing yet - love notes from classmates and teachers will show up here.</p>`;

    // Articles preview
    const arts = DB.read("calmio_articles", []).sort((a, b) => b.ts - a.ts).slice(0, 3);
    document.getElementById("student-articles").innerHTML =
      arts.map(a => this.articleRow(a)).join("") +
      `<button class="btn secondary small" onclick="app.show('articles')">See all articles</button>`;

    // Upcoming sessions
    const sessions = DB.read("calmio_slots", [])
      .filter(s => s.bookedBy === this.me.id && s.start > now())
      .sort((a, b) => a.start - b.start);
    document.getElementById("student-sessions").innerHTML = sessions.length
      ? sessions.map(s => this.sessionRow(s, "student")).join("")
      : `<p class="muted">No sessions yet. <a href="#" onclick="app.show('schedule');return false">Book time with a counselor</a></p>`;

    // Past conversations
    const mine = DB.read("calmio_thoughts", []).filter(t => t.fromId === this.me.id).sort((a, b) => b.ts - a.ts);
    document.getElementById("student-convos").innerHTML = mine.length
      ? mine.map(t => {
          const replies = t.replies.length ? ` \u00b7 ${t.replies.length} repl${t.replies.length > 1 ? "ies" : "y"}` : "";
          return `<div class="list-item">
            <a href="#" onclick="app.openConvo('${t.id}');return false">${esc(t.body.slice(0, 60))}${t.body.length > 60 ? "..." : ""}</a>
            ${t.urgent ? '<span class="pill" style="background:var(--signal-soft);color:var(--signal)">priority</span>' : ""}
            <div class="tiny">${timeAgo(t.ts)}${replies}</div>
          </div>`;
        }).join("")
      : `<p class="muted">When you share your thoughts, the conversation with the counseling team appears here.</p>`;
  },

  /* ---------- teacher home ---------- */
  renderTeacherHome() {
    document.getElementById("teacher-greeting").textContent =
      "How can I help you, " + disp(this.me) + "?";

    // Recent messages (every counselor sees all of them)
    const inbox = DB.read("calmio_thoughts", []).sort((a, b) => (b.urgent - a.urgent) || (b.ts - a.ts));
    document.getElementById("teacher-inbox").innerHTML = inbox.length
      ? inbox.slice(0, 6).map(t => {
          const band = moodBand(t.mood, t.risk);
          return `<div class="list-item">
            <a href="#" onclick="app.openStudentByThought('${t.id}');return false">${esc(this.displayNameOf(t))}</a>
            ${t.urgent ? '<span class="pill" style="background:var(--signal-soft);color:var(--signal)">PRIORITY</span>' : ""}
            <span class="pill ${band.cls}">${band.label.split(" - ")[0]}</span>
            <div class="muted">${esc(t.body.slice(0, 90))}${t.body.length > 90 ? "..." : ""}</div>
            <div class="tiny">${timeAgo(t.ts)} \u00b7 ${t.replies.length} repl${t.replies.length === 1 ? "y" : "ies"}</div>
          </div>`;
        }).join("")
      : `<p class="muted">No messages yet. When students share their thoughts, they appear here for the whole counseling team.</p>`;

    // Upcoming sessions with me
    const sessions = DB.read("calmio_slots", [])
      .filter(s => s.teacherId === this.me.id && s.start > now() - 3600e3)
      .sort((a, b) => a.start - b.start);
    document.getElementById("teacher-sessions").innerHTML = sessions.length
      ? sessions.map(s => {
          const link = gcalLink(
            `Calmio session - ${s.bookedName} with ${this.me.name}`,
            s.start, s.minutes,
            `Support session booked through Calmio.\nStudent: ${s.bookedName}\nCounselor: ${this.me.name}`);
          return `<div class="list-item">
            <b>${fmtSlot(s.start, s.minutes)}</b> <span class="pill love">${esc(s.bookedName)}</span><br />
            <a class="gcal-btn" href="${link}" target="_blank" rel="noopener">Add to Google Calendar</a>
          </div>`;
        }).join("")
      : `<p class="muted">No booked sessions yet. Students can book any free school hour with you - no setup needed.</p>`;

    const loves = DB.read("calmio_loves", []).filter(l => l.toId === this.me.id).sort((a, b) => b.ts - a.ts);
    document.getElementById("teacher-loves").innerHTML = loves.length
      ? loves.slice(0, 5).map(l =>
          `<div class="notice"><b>${esc(l.fromName)}</b> sent you a <b>love</b> for your <i>${esc(l.reason)}</i>! <span class="tiny">${timeAgo(l.ts)}</span></div>`).join("")
      : `<p class="muted">No love notes yet.</p>`;

    const mine = DB.read("calmio_articles", []).filter(a => a.byName === this.me.name).sort((a, b) => b.ts - a.ts);
    document.getElementById("teacher-articles").innerHTML = mine.length
      ? mine.map(a => this.articleRow(a)).join("")
      : `<p class="muted">Articles you publish appear here and on every student's home page.</p>`;
  },

  /* ---------- Students tab (teachers) ----------
     Identity keys: "user:<id>" for named messages, "anon:<id>" for
     anonymous ones. The same student sending both ways appears as two
     separate pages, so anonymity is preserved. */
  identityKey(t) { return (t.anonymous ? "anon:" : "user:") + t.fromId; },

  displayNameOf(t) {
    const u = DB.read("calmio_users", []).find(x => x.id === t.fromId);
    if (!t.anonymous) return u ? disp(u) : (t.fromName || "A student");
    return "#" + (u && u.anonId ? u.anonId : "student0000");
  },

  buildStudentIndex() {
    const thoughts = DB.read("calmio_thoughts", []);
    const map = new Map();      // key -> { key, name, last }
    for (const t of thoughts) {
      const key = this.identityKey(t);
      const rec = map.get(key) || { key, name: this.displayNameOf(t), last: 0 };
      rec.last = Math.max(rec.last, t.ts);
      map.set(key, rec);
    }
    let list = [...map.values()].sort((a, b) => b.last - a.last);
    if (this.studentQuery) {
      const q = this.studentQuery.toLowerCase();
      list = list.filter(r => r.name.toLowerCase().includes(q));
    }
    this.studentKeys = list;
    if (this.studentIdx >= list.length) this.studentIdx = 0;
  },

  renderStudents() {
    this.buildStudentIndex();
    const counter = document.getElementById("student-counter");
    const page = document.getElementById("student-page");
    if (!this.studentKeys.length) {
      counter.textContent = "";
      page.innerHTML = `<p class="muted" style="text-align:center;margin-top:20px">${
        this.studentQuery ? "No student matches that search." :
        "No students have shared anything yet. As soon as someone does, their page appears here."}</p>`;
      return;
    }
    const rec = this.studentKeys[this.studentIdx];
    counter.textContent = `Student ${this.studentIdx + 1} of ${this.studentKeys.length}`;

    const thoughts = DB.read("calmio_thoughts", [])
      .filter(t => this.identityKey(t) === rec.key)
      .sort((a, b) => a.ts - b.ts);
    const latest = thoughts[thoughts.length - 1];
    const band = moodBand(latest.mood, latest.risk);
    const isAnon = rec.key.startsWith("anon:");
    const student = DB.read("calmio_users", []).find(u => u.id === rec.key.split(":")[1]);
    const photo = (!isAnon && student && student.profile && student.profile.photo) ? student.profile.photo : null;
    const cls = (!isAnon && student && student.profile && student.profile.className) ? student.profile.className : "";

    // Notes
    const allNotes = DB.read("calmio_notes", {});
    const notes = (allNotes[rec.key] || []).sort((a, b) => b.ts - a.ts);

    page.innerHTML = `
      <div class="student-head">
        <div class="avatar big">${photo ? `<img src="${photo}" alt="" />` : esc(rec.name.replace("#", "").trim()[0].toUpperCase())}</div>
        <div>
          <h2 style="margin:0">${esc(rec.name)}</h2>
          <p class="tiny" style="margin:2px 0 6px">${isAnon ? "Anonymous student (identity hidden by their choice)" : (cls ? "Class " + esc(cls) : "Student")} \u00b7 ${thoughts.length} message${thoughts.length > 1 ? "s" : ""} \u00b7 last ${timeAgo(latest.ts)}</p>
          <span class="pill ${band.cls}">AI evaluation: ${band.label}</span>
        </div>
      </div>

      <h3 class="subhead">Mental health over time</h3>
      <p class="tiny">Each point is the AI's read of one message, from 0 (very low) to 100 (doing well). Demo: rule-based - connect a real model via your server for production.</p>
      ${this.moodGraph(thoughts)}

      <h3 class="subhead">Messages</h3>
      ${thoughts.slice().reverse().map(t => `
        <div class="list-item">
          <a href="#" onclick="app.openConvo('${t.id}','students');return false">${esc(t.body.slice(0, 90))}${t.body.length > 90 ? "..." : ""}</a>
          ${t.urgent ? '<span class="pill" style="background:var(--signal-soft);color:var(--signal)">PRIORITY</span>' : ""}
          <div class="tiny">${timeAgo(t.ts)} \u00b7 mood ${t.mood} \u00b7 ${t.replies.length} repl${t.replies.length === 1 ? "y" : "ies"}</div>
        </div>`).join("")}

      <h3 class="subhead">Progress notes (visible to counselors only)</h3>
      <textarea id="note-body" style="min-height:70px" placeholder="e.g. Met after class - exam stress easing, agreed to check in again on Friday."></textarea>
      <button class="btn small" onclick="app.addNote()">Add note</button>
      <div style="margin-top:10px">
        ${notes.length ? notes.map(n => `
          <div class="note-item">
            <div>${esc(n.text)}</div>
            <span class="tiny">${esc(n.byName)} \u00b7 ${timeAgo(n.ts)}</span>
          </div>`).join("") : `<p class="muted">No notes yet. Notes help the whole team follow this student's progress.</p>`}
      </div>`;
  },

  moodGraph(thoughts) {
    const pts = thoughts.map(t => ({ ts: t.ts, mood: t.mood, risk: t.risk }));
    const W = 640, H = 200, padL = 34, padR = 14, padT = 14, padB = 26;
    const iw = W - padL - padR, ih = H - padT - padB;
    const minT = pts[0].ts, maxT = pts[pts.length - 1].ts;
    const span = Math.max(maxT - minT, 1);
    const X = ts => pts.length === 1 ? padL + iw / 2 : padL + (ts - minT) / span * iw;
    const Y = m => padT + (1 - m / 100) * ih;
    const color = p => p.risk || p.mood <= 30 ? "var(--signal)" : p.mood <= 50 ? "var(--gold)" : "var(--cacao)";
    const line = pts.length > 1
      ? `<polyline fill="none" stroke="var(--cacao)" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"
           points="${pts.map(p => X(p.ts).toFixed(1) + "," + Y(p.mood).toFixed(1)).join(" ")}" opacity="0.7"/>` : "";
    const dots = pts.map(p =>
      `<circle cx="${X(p.ts).toFixed(1)}" cy="${Y(p.mood).toFixed(1)}" r="5" fill="${color(p)}"/>`).join("");
    const grid = [0, 50, 100].map(v =>
      `<line x1="${padL}" y1="${Y(v)}" x2="${W - padR}" y2="${Y(v)}" stroke="var(--oat-line)" stroke-width="1"/>
       <text x="${padL - 6}" y="${Y(v) + 4}" text-anchor="end" font-size="11" fill="var(--ink-soft)">${v}</text>`).join("");
    const fmtD = ts => new Date(ts).toLocaleDateString(undefined, { month: "short", day: "numeric" });
    const xlabels = pts.length > 1
      ? `<text x="${padL}" y="${H - 8}" font-size="11" fill="var(--ink-soft)">${fmtD(minT)}</text>
         <text x="${W - padR}" y="${H - 8}" text-anchor="end" font-size="11" fill="var(--ink-soft)">${fmtD(maxT)}</text>`
      : `<text x="${W / 2}" y="${H - 8}" text-anchor="middle" font-size="11" fill="var(--ink-soft)">${fmtD(minT)}</text>`;
    return `<div class="mood-graph"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Mood over time">${grid}${line}${dots}${xlabels}</svg></div>`;
  },

  prevStudent() {
    if (!this.studentKeys.length) return;
    this.studentIdx = (this.studentIdx - 1 + this.studentKeys.length) % this.studentKeys.length;
    this.renderStudents();
  },
  nextStudent() {
    if (!this.studentKeys.length) return;
    this.studentIdx = (this.studentIdx + 1) % this.studentKeys.length;
    this.renderStudents();
  },
  searchStudent(q) {
    this.studentQuery = q.trim();
    this.studentIdx = 0;
    this.renderStudents();
  },

  openStudentByThought(id) {
    const t = DB.read("calmio_thoughts", []).find(x => x.id === id);
    if (!t) return;
    this.studentQuery = "";
    document.getElementById("student-search").value = "";
    this.show("students");
    const key = this.identityKey(t);
    const idx = this.studentKeys.findIndex(r => r.key === key);
    if (idx >= 0) { this.studentIdx = idx; this.renderStudents(); }
  },

  addNote() {
    const body = document.getElementById("note-body").value.trim();
    if (!body) { this.toast("Write the note first."); return; }
    const rec = this.studentKeys[this.studentIdx];
    if (!rec) return;
    const all = DB.read("calmio_notes", {});
    (all[rec.key] = all[rec.key] || []).push({ id: uid(), byName: disp(this.me), text: body, ts: now() });
    DB.write("calmio_notes", all);
    this.toast("Note added.");
    this.renderStudents();
  },

  /* ---------- scheduling (weekly calendar, no setup needed) ---------- */
  renderSchedule() {
    const sel = document.getElementById("sched-teacher");
    sel.innerHTML = this.teachers().map(t => `<option value="${t.id}">${esc(disp(t))}</option>`).join("");
    this.weekOffset = 0;
    this.renderWeek();
    this.renderMySessions();
  },

  changeWeek(dir) {
    this.weekOffset = Math.max(0, this.weekOffset + dir);   // no browsing the past
    this.renderWeek();
  },

  renderWeek() {
    const teacherId = document.getElementById("sched-teacher").value;
    const s = getSettings();
    const hStart = Math.floor(s.hoursStart), hEnd = Math.ceil(s.hoursEnd);
    const week = startOfWeek(this.weekOffset);
    // Full week Mon-Sun. Weekend columns render dark (school closed) and are
    // hidden entirely on small screens, where only Mon-Fri fits.
    const days = [...Array(7)].map((_, i) => { const d = new Date(week); d.setDate(d.getDate() + i); return d; });

    const label = document.getElementById("week-label");
    const fmtD = d => d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
    label.textContent = (this.weekOffset === 0 ? "This week: " : this.weekOffset === 1 ? "Next week: " : "") +
      fmtD(days[0]) + " - " + fmtD(days[6]);

    const slots = DB.read("calmio_slots", []).filter(x => x.teacherId === teacherId);
    const findBooking = start => slots.find(x => x.start === start);
    const isWknd = i => i >= 5;   // Sat, Sun

    let html = `<table class="cal-table"><thead><tr><th class="cal-hourcol"></th>`;
    days.forEach((d, i) => {
      html += `<th class="${isWknd(i) ? "wknd" : ""}">${d.toLocaleDateString(undefined, { weekday: "short" })}<span class="cal-date">${fmtD(d)}</span></th>`;
    });
    html += `</tr></thead><tbody>`;
    for (let h = hStart; h < hEnd; h++) {
      const hh = ((h % 12) || 12) + (h < 12 ? " AM" : " PM");
      html += `<tr><th class="cal-hourcol">${hh}</th>`;
      days.forEach((d, i) => {
        if (isWknd(i)) { html += `<td class="cal-cell wknd" aria-label="School closed"></td>`; return; }
        const start = new Date(d); start.setHours(h, 0, 0, 0);
        const ms = start.getTime();
        const booking = findBooking(ms);
        if (booking && booking.bookedBy === this.me.id) {
          html += `<td class="cal-cell mine"><button onclick="app.cancelBooking('${booking.id}')" title="Tap to cancel">Yours</button></td>`;
        } else if (booking) {
          html += `<td class="cal-cell taken">Booked</td>`;
        } else if (now() > ms - BOOK_CUTOFF_MS) {
          html += `<td class="cal-cell closed"></td>`;
        } else {
          html += `<td class="cal-cell free"><button onclick="app.bookHour('${teacherId}', ${ms})" aria-label="Book ${hh}">Book</button></td>`;
        }
      });
      html += `</tr>`;
    }
    html += `</tbody></table>`;
    document.getElementById("week-grid").innerHTML = html;
  },

  bookHour(teacherId, startMs) {
    if (now() > startMs - BOOK_CUTOFF_MS) {
      this.toast("That hour starts too soon - sessions can be booked up to 30 minutes before they start.");
      this.renderWeek(); return;
    }
    const slots = DB.read("calmio_slots", []);
    if (slots.some(x => x.teacherId === teacherId && x.start === startMs)) {
      this.toast("Sorry - that hour was just taken."); this.renderWeek(); return;
    }
    const teacher = this.teachers().find(t => t.id === teacherId);
    slots.push({ id: uid(), teacherId, teacherName: teacher ? disp(teacher) : "Counselor",
                 start: startMs, minutes: 60, bookedBy: this.me.id, bookedName: disp(this.me) });
    DB.write("calmio_slots", slots);
    this.toast("Session booked with " + (teacher ? disp(teacher) : "your counselor") + ".");
    this.creditWater("booking");
    this.renderWeek();
    this.renderMySessions();
  },

  cancelBooking(id) {
    const slots = DB.read("calmio_slots", []);
    const s = slots.find(x => x.id === id);
    if (!s || s.bookedBy !== this.me.id) return;
    DB.write("calmio_slots", slots.filter(x => x.id !== id));
    this.toast("Booking cancelled - the hour is free again.");
    if (document.getElementById("view-schedule").classList.contains("visible")) {
      this.renderWeek(); this.renderMySessions();
    } else { this.renderStudentHome(); }
  },

  sessionRow(s) {
    const link = gcalLink(
      `Calmio session - ${s.bookedName} with ${s.teacherName}`,
      s.start, s.minutes,
      `Support session booked through Calmio.\nStudent: ${s.bookedName}\nCounselor: ${s.teacherName}`);
    return `<div class="list-item">
      <b>${esc(s.teacherName)}</b><br />
      <span class="tiny">${fmtSlot(s.start, s.minutes)}</span><br />
      <a class="gcal-btn" href="${link}" target="_blank" rel="noopener">Add to Google Calendar</a>
      <button class="linklike" onclick="app.cancelBooking('${s.id}')" style="margin-left:8px">cancel</button>
    </div>`;
  },

  renderMySessions() {
    const mine = DB.read("calmio_slots", [])
      .filter(s => s.bookedBy === this.me.id && s.start > now())
      .sort((a, b) => a.start - b.start);
    document.getElementById("sched-mine").innerHTML = mine.length
      ? mine.map(s => this.sessionRow(s)).join("")
      : `<p class="muted">Nothing booked yet.</p>`;
  },

  /* ---------- share ---------- */
  renderShare() {
    if (this.me.role === "teacher") {
      this.shareTab("love");
      document.getElementById("tab-thoughts").style.display = "none";
    } else {
      document.getElementById("tab-thoughts").style.display = "";
      this.shareTab("thoughts");
    }
    const lSel = document.getElementById("love-to");
    lSel.innerHTML = DB.read("calmio_users", [])
      .filter(u => u.id !== this.me.id)
      .map(u => `<option value="${u.id}">${esc(disp(u))} (${u.role === "teacher" ? "counselor" : u.role})</option>`).join("");
  },

  shareTab(tab) {
    document.getElementById("tab-thoughts").classList.toggle("active", tab === "thoughts");
    document.getElementById("tab-love").classList.toggle("active", tab === "love");
    document.getElementById("share-thoughts-pane").hidden = tab !== "thoughts";
    document.getElementById("share-love-pane").hidden = tab !== "love";
  },

  sendThought() {
    const body = document.getElementById("thought-body").value.trim();
    if (!body) { this.toast("Write something first - even a sentence is enough."); return; }
    const ev = evaluateMood(body);
    const thoughts = DB.read("calmio_thoughts", []);
    thoughts.push({
      id: uid(), fromId: this.me.id, fromName: disp(this.me),
      toId: "all", anonymous: document.getElementById("thought-anon").checked,
      urgent: false, body, ts: now(), replies: [],
      mood: ev.score, risk: ev.risk
    });
    DB.write("calmio_thoughts", thoughts);
    document.getElementById("thought-body").value = "";
    this.toast("Sent privately to the counseling team. Thank you for sharing.");
    this.creditWater("journal");
    this.backHome();
    if (ev.risk) this.openCheckin();   // message still reaches the counselors either way
  },

  sendLove() {
    const toId = document.getElementById("love-to").value;
    const reason = document.getElementById("love-reason").value.trim();
    if (!reason) { this.toast("Tell them what it's for!"); return; }
    const to = DB.read("calmio_users", []).find(u => u.id === toId);
    const loves = DB.read("calmio_loves", []);
    loves.push({
      id: uid(), toId, toName: to ? disp(to) : "",
      fromName: document.getElementById("love-anon").checked ? "Anonymous" : disp(this.me),
      reason, ts: now()
    });
    DB.write("calmio_loves", loves);
    document.getElementById("love-reason").value = "";
    this.toast("Love sent.");
    this.creditWater("love");
    this.backHome();
  },

  /* ---------- conversations ---------- */
  openConvo(id, from) {
    this.openThoughtId = id;
    this._convoFrom = from || null;
    const t = DB.read("calmio_thoughts", []).find(x => x.id === id);
    if (!t) return;
    const iAmSender = t.fromId === this.me.id;
    document.getElementById("convo-title").textContent = iAmSender
      ? "Conversation with the counseling team"
      : "Conversation with " + this.displayNameOf(t);

    const rows = [
      { fromId: t.fromId, name: t.anonymous && !iAmSender ? this.displayNameOf(t) : t.fromName, body: t.body, ts: t.ts },
      ...t.replies
    ];
    document.getElementById("convo-thread").innerHTML = rows.map(r => `
      <div class="bubble ${r.fromId === this.me.id ? "mine" : ""}">
        ${esc(r.body)}
        <span class="tiny">${esc(r.name)} \u00b7 ${timeAgo(r.ts)}</span>
      </div>`).join("");
    this.show("convo");
  },

  convoBack() {
    if (this._convoFrom === "students") this.show("students");
    else this.backHome();
  },

  sendReply() {
    const body = document.getElementById("convo-reply").value.trim();
    if (!body) return;
    const thoughts = DB.read("calmio_thoughts", []);
    const t = thoughts.find(x => x.id === this.openThoughtId);
    if (!t) return;
    t.replies.push({ fromId: this.me.id, name: disp(this.me), body, ts: now() });
    DB.write("calmio_thoughts", thoughts);
    document.getElementById("convo-reply").value = "";
    this.openConvo(t.id, this._convoFrom);
  },

  /* ---------- articles ---------- */
  articleRow(a) {
    return `<div class="list-item">
      <a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.title)}</a>
      <div class="tiny">read time: ${a.minutes} min \u00b7 ${esc(a.byName)}, ${timeAgo(a.ts)}</div>
      <div>${a.keywords.split(",").map(k => `<span class="pill">${esc(k.trim())}</span>`).join("")}</div>
    </div>`;
  },

  renderArticles() {
    const arts = DB.read("calmio_articles", []).sort((a, b) => b.ts - a.ts);
    document.getElementById("articles-full").innerHTML = arts.map(a => this.articleRow(a)).join("");
  },

  estimateMinutes(url, title, keywords) {
    if (/youtube\.com|youtu\.be|vimeo\.com/i.test(url)) return 4;         // typical short video
    const words = (title + " " + keywords).split(/\s+/).length;
    return Math.max(2, Math.min(10, Math.round(words / 2)));              // rough article guess
  },

  publishArticle() {
    const url = document.getElementById("art-url").value.trim();
    const title = document.getElementById("art-title").value.trim();
    const keywords = document.getElementById("art-keywords").value.trim();
    let minutes = parseInt(document.getElementById("art-minutes").value, 10);
    if (!url || !title) { this.toast("A link and a title are required."); return; }
    if (!/^https?:\/\//i.test(url)) { this.toast("The link must start with http:// or https://"); return; }
    if (!minutes || minutes < 1) minutes = this.estimateMinutes(url, title, keywords);
    const arts = DB.read("calmio_articles", []);
    arts.push({ id: uid(), title, url, keywords: keywords || "General", minutes, byName: this.me.name, ts: now() });
    DB.write("calmio_articles", arts);
    ["art-url", "art-title", "art-keywords", "art-minutes"].forEach(i => document.getElementById(i).value = "");
    this.toast("Published - students can see it now.");
    this.renderTeacherHome();
  },

  /* ---------- account manager (opened from the avatar) ---------- */
  renderAccount() {
    const p = this.me.profile || {};
    document.getElementById("prof-fullname").value = p.fullName || "";
    document.getElementById("prof-nickname").value = p.nickname || "";
    document.getElementById("prof-dob").value = p.dob || "";
    document.getElementById("prof-hobbies").value = p.hobbies || "";
    document.getElementById("prof-clubs").value = p.clubs || "";

    // School and class are fixed once set
    const schoolInput = document.getElementById("prof-school");
    const classInput = document.getElementById("prof-class");
    schoolInput.value = p.school || "";
    classInput.value = p.className || "";
    schoolInput.disabled = !!p.school;
    classInput.disabled = !!p.className;
    document.getElementById("school-lock").hidden = !p.school;
    document.getElementById("class-lock").hidden = !p.className;

    const av = document.getElementById("account-avatar");
    av.innerHTML = p.photo ? `<img src="${p.photo}" alt="Your photo" />` : esc(disp(this.me).trim()[0].toUpperCase());

    document.getElementById("sec-lockmin").value = this.lockMinutes();
    document.getElementById("sec-newpass").value = "";
    document.getElementById("sec-curpass").value = "";
  },

  photoPicked(ev) {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    if (!/^image\//.test(file.type)) { this.toast("Please choose an image file."); return; }
    const img = new Image();
    const reader = new FileReader();
    reader.onload = () => {
      img.onload = () => {
        // Downscale to 160px so it fits comfortably in storage
        const size = 160;
        const canvas = document.createElement("canvas");
        canvas.width = canvas.height = size;
        const ctx = canvas.getContext("2d");
        const min = Math.min(img.width, img.height);
        ctx.drawImage(img, (img.width - min) / 2, (img.height - min) / 2, min, min, 0, 0, size, size);
        this.me.profile = this.me.profile || {};
        this.me.profile.photo = canvas.toDataURL("image/jpeg", 0.85);
        this.saveMe();
        this.renderAccount();
        this.renderAvatar();
        this.toast("Photo updated.");
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  },

  saveProfile() {
    /* display name follows the full name field */
    const p = this.me.profile = this.me.profile || {};
    p.fullName = document.getElementById("prof-fullname").value.trim();
    p.nickname = document.getElementById("prof-nickname").value.trim();
    p.dob = document.getElementById("prof-dob").value;
    p.hobbies = document.getElementById("prof-hobbies").value.trim();
    p.clubs = document.getElementById("prof-clubs").value.trim();
    if (p.fullName) this.me.display = p.fullName;
    // School / class: only writable while still empty - fixed afterwards
    if (!p.school)    p.school    = document.getElementById("prof-school").value.trim();
    if (!p.className) p.className = document.getElementById("prof-class").value.trim();
    this.saveMe();
    this.renderAccount();
    this.renderAvatar();
    this.toast("Profile saved.");
  },

  async saveSecurity() {
    // Auto-lock minutes
    const mins = parseInt(document.getElementById("sec-lockmin").value, 10);
    if (mins >= 1 && mins <= 60) this.me.lockMinutes = mins;

    // Optional password change (requires current password)
    const newPass = document.getElementById("sec-newpass").value;
    const curPass = document.getElementById("sec-curpass").value;
    if (newPass) {
      if (newPass.length < 6) { this.toast("New password must be at least 6 characters."); return; }
      if (Remote.on) {
        const res = await Remote.changePassword(curPass, newPass);
        if (res.error) { this.toast(res.error + " Password not changed."); return; }
      } else {
        const res = await verifyPass(this.me, curPass);
        if (!res.ok) { this.toast("Current password is wrong - password not changed."); return; }
        this.me.salt = newSalt();
        this.me.passHash = await makeHash(newPass, this.me.salt);
      }
      this.toast("Password changed and security settings saved.");
    } else {
      this.toast("Security settings saved.");
    }
    this.saveMe();
    this.renderAccount();
  },

  /* ---------- delete account flow ---------- */
  openDelete() {
    this.deleteDraft = { rating: 0 };
    document.getElementById("del-reason").value = "";
    document.getElementById("del-message").value = "";
    this.setStars(0);
    document.getElementById("delete-step1").hidden = false;
    document.getElementById("delete-step2").hidden = true;
    document.getElementById("delete-backdrop").classList.add("open");
  },

  closeDelete() {
    document.getElementById("delete-backdrop").classList.remove("open");
  },

  setStars(n) {
    this.deleteDraft.rating = n;
    document.querySelectorAll("#del-stars button").forEach((b, i) =>
      b.classList.toggle("on", i < n));
  },

  deleteNext() {
    const reason = document.getElementById("del-reason").value;
    const message = document.getElementById("del-message").value.trim();
    if (!reason) { this.toast("Please choose a reason first."); return; }
    if (!this.deleteDraft.rating) { this.toast("Please tap a star rating."); return; }
    if (!message) { this.toast("Even one honest sentence helps us."); return; }
    this.deleteDraft.reason = reason;
    this.deleteDraft.message = message;
    document.getElementById("delete-step1").hidden = true;
    document.getElementById("delete-step2").hidden = false;
  },

  deleteFinish(allowed) {
    const d = this.deleteDraft;
    const p = this.me.profile || {};

    // Always keep the feedback privately, so the school can learn from it
    const feedback = DB.read("calmio_feedback", []);
    feedback.push({ id: uid(), role: this.me.role, reason: d.reason,
                    rating: d.rating, message: d.message, allowed, ts: now() });
    DB.write("calmio_feedback", feedback);

    // Publish to "People we have helped" ONLY if: permission given,
    // a full 5-star rating, and the words themselves are kind.
    if (allowed && d.rating === 5 && isKindMessage(d.message)) {
      const testimonials = DB.read("calmio_testimonials", []);
      testimonials.unshift({
        id: uid(),
        name: p.nickname || disp(this.me),
        photo: p.photo || null,
        rating: d.rating,
        message: d.message,
        ts: now()
      });
      DB.write("calmio_testimonials", testimonials.slice(0, 20));
    }

    if (Remote.on) {
      // Feedback/testimonial rows above were already pushed. The account
      // itself (and everything tied to it, via cascades) is removed by a
      // server function holding the service-role key.
      Remote.deleteAccount().then(res => {
        if (res.error) { this.toast("Deleting on the server failed: " + res.error); }
      });
      Remote.signOut();
      this.closeDelete();
      this.me = null;
      document.getElementById("topbar").hidden = true;
      this.authTab("login");
      this.show("welcome");
      this.renderTestimonials();
      this.toast("Your account has been deleted. Take care of yourself.");
      return;
    }

    // Remove the account and everything tied to it
    const myId = this.me.id;
    DB.write("calmio_users", DB.read("calmio_users", []).filter(u => u.id !== myId));
    DB.write("calmio_thoughts", DB.read("calmio_thoughts", []).filter(t => t.fromId !== myId && t.toId !== myId));
    DB.write("calmio_loves", DB.read("calmio_loves", []).filter(l => l.toId !== myId));
    DB.write("calmio_slots", DB.read("calmio_slots", [])
      .filter(s => s.teacherId !== myId && s.bookedBy !== myId));
    const notes = DB.read("calmio_notes", {});
    delete notes["user:" + myId];
    delete notes["anon:" + myId];
    DB.write("calmio_notes", notes);
    const gardens = DB.read("calmio_garden", {});
    delete gardens[myId];
    DB.write("calmio_garden", gardens);
    sessionStorage.removeItem("calmio_session");

    this.closeDelete();
    this.me = null;
    document.getElementById("topbar").hidden = true;
    this.authTab("login");
    this.show("welcome");
    this.renderTestimonials();
    this.toast("Your account has been deleted. Take care of yourself.");
  },

  /* ---------- People we have helped ---------- */
  renderTestimonials() {
    const list = DB.read("calmio_testimonials", [])
      .filter(t => t.rating === 5 && isKindMessage(t.message));
    const card = document.getElementById("testimonials-card");
    card.hidden = list.length === 0;
    document.getElementById("testimonials-list").innerHTML = list.map(t => `
      <div class="testimonial">
        <div class="avatar">${t.photo ? `<img src="${t.photo}" alt="" />` : esc((t.name || "?").trim()[0].toUpperCase())}</div>
        <div>
          <b>${esc(t.name)}</b>
          <div>${starsRow(5)}</div>
          <blockquote>"${esc(t.message)}"</blockquote>
          <span class="tiny">${timeAgo(t.ts)}</span>
        </div>
      </div>`).join("");
  },

  /* ---------- emergency ---------- */
  renderEmergency() {
    document.getElementById("crisis-lines-list").innerHTML = crisisLinesHTML();
    // Counselor line appears here during school hours (set by an administrator)
    document.getElementById("crisis-counselor-slot").innerHTML = counselorLine();
  },

  sendUrgent() {
    const body = document.getElementById("em-body").value.trim();
    if (!body) { this.toast("Tell them briefly what's going on."); return; }
    const ev = evaluateMood(body);
    const thoughts = DB.read("calmio_thoughts", []);
    thoughts.push({
      id: uid(), fromId: this.me.id, fromName: disp(this.me),
      toId: "all", anonymous: false, urgent: true, body, ts: now(), replies: [],
      mood: ev.score, risk: ev.risk
    });
    DB.write("calmio_thoughts", thoughts);
    document.getElementById("em-body").value = "";
    this.toast("Priority message sent. Every counselor sees it clearly marked.");
    this.backHome();
    if (ev.risk) this.openCheckin();
  },

  /* ---------- check-in pop-up (after a concerning message) ---------- */
  openCheckin() {
    document.getElementById("checkin-step1").hidden = false;
    document.getElementById("checkin-step2").hidden = true;
    document.getElementById("checkin-backdrop").classList.add("open");
  },

  closeCheckin() {
    document.getElementById("checkin-backdrop").classList.remove("open");
  },

  checkinAnswer(answer) {
    if (answer === "yes") {
      document.getElementById("checkin-lines").innerHTML =
        counselorLine() + crisisLinesHTML();
      document.getElementById("checkin-step1").hidden = true;
      document.getElementById("checkin-step2").hidden = false;
    } else if (answer === "help") {
      this.closeCheckin();
      this.show("emergency");
    } else {
      this.closeCheckin();
      this.toast("Okay. We're glad you're here. Reach out any time.");
    }
  },

  /* ----- AI helper (demo, rule-based) -----
     To connect a real AI model, replace demoReply() with a fetch()
     to YOUR OWN server endpoint (e.g. a Netlify/Vercel serverless
     function) that holds the API key. Never put an API key in this
     file - anyone can read client-side JavaScript.               */
  async sendChat() {
    const input = document.getElementById("chat-input");
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    this.addChat(text, "user");
    // Try the school's own AI endpoint first (netlify/functions/chat.js,
    // deployed with the site - see DEPLOYMENT.md). If it isn't deployed or
    // doesn't answer within 9 seconds, fall back to the built-in demo script.
    let reply = "";
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 9000);
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text }),
        signal: ctl.signal
      });
      clearTimeout(timer);
      if (res.ok) {
        const data = await res.json();
        reply = (data.reply || "").trim();
      }
    } catch (e) { /* endpoint not deployed - use the demo */ }
    this.addChat(reply || this.demoReply(text), "bot");
  },

  addChat(text, who) {
    const log = document.getElementById("chatlog");
    const row = document.createElement("div");
    row.className = "chatrow" + (who === "user" ? " user" : "");
    const msg = document.createElement("div");
    msg.className = "chatmsg";
    msg.textContent = text;
    row.appendChild(msg);
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
  },

  demoReply(text) {
    const q = text.toLowerCase();
    if (/(suicid|self.?harm|hurt (them|him|her)self|kill)/.test(q)) {
      return "If a student mentions self-harm or suicide, treat it as urgent: stay calm, take it seriously, and involve your school counselor or crisis team today - this is beyond what any teacher (or chatbot) should carry alone. Don't promise secrecy; do tell the student you're getting them support because you care.";
    }
    if (/(test|exam).*(easier|easy)|easier.*(test|exam)/.test(q)) {
      return "Making the test easier for everyone usually isn't the right lever - it doesn't address this student's anxiety and can feel unfair. Better options: offer this student extra time or a quieter room, break the test into sections, or teach a calming routine before exams. If anxiety keeps affecting their schoolwork, loop in the counselor about formal accommodations.";
    }
    if (/grade|unreleased/.test(q)) {
      return "For students pressing about unreleased grades: acknowledge the anxiety behind the question, give a clear date when grades will be out, and hold that line consistently for everyone. If one student asks repeatedly, that anxiety itself might be the thing worth a caring conversation.";
    }
    if (/anxi|stress|panic/.test(q)) {
      return "Start by listening without fixing: name what you're seeing ('you seem really stressed lately - want to talk?'). Small accommodations like a short break or a check-in routine help. If the anxiety is frequent or intense, connect them with the school counselor rather than managing it alone.";
    }
    if (/parent|home|family/.test(q)) {
      return "Family situations are delicate - focus on what the student needs at school, avoid criticizing their family, and document your concerns. If you suspect harm at home, you're likely a mandatory reporter: talk to your counselor or administrator about the proper steps right away.";
    }
    return "Here's a frame that works for most situations: (1) listen first and reflect back what you heard, (2) ask what would help before prescribing, (3) make one small, fair accommodation if appropriate, and (4) involve the school counselor whenever something feels heavier than a classroom issue. Want to give me more detail about the situation?";
  }
};


/* =====================================================================
   THE GARDEN - a gentle flower-growing game for students
   ---------------------------------------------------------------------
   - The garden starts with one small sprout; the pond, tree and fence
     are already there.
   - Each flower takes GROW_DAYS watered days to go sprout -> bloom.
     When it blooms you receive a NEW random flower (item-drop reveal),
     planted at a random free spot.
   - Watering costs 1 water per flower per day (2 flowers = 2 water...).
   - Earning (base, week 1): login 0.2 / journal 1 / love 0.4 / booking 0.4.
     Rates double each week up to x8 (week 4+). Daily earning is capped
     at flowers + GARDEN_CAP_BONUS.
     Tuning: with x8 a journal entry alone covers watering until the
     garden reaches 9 flowers (~2 months of steady care); after that
     you top up with login, love and booking.
   - Nothing ever dies. An unwatered flower simply waits.
   ===================================================================== */

const GARDEN_BASE = { login: 0.2, journal: 1, love: 0.4, booking: 0.4 };
const GARDEN_EARN_LABELS = {
  login: "Visit Calmio (daily)", journal: "Write a journal entry (Share your thoughts)",
  love: "Send someone appreciation", booking: "Book a session with a counselor"
};
const GARDEN_CAP_BONUS = 2;
const GARDEN_MAX_MULT = 8;
const GROW_DAYS = 7;

/* 18 species across 9 head shapes - colors are [petal, petal-deep, center] */
const FLOWER_SPECIES = [
  { name: "Sunbeam Daisy",     shape: "daisy",   c: ["#ffffff", "#f2ead8", "#e8b64c"] },
  { name: "Blush Daisy",       shape: "daisy",   c: ["#f3c1cd", "#e39cae", "#e8b64c"] },
  { name: "Rosewood Tulip",    shape: "tulip",   c: ["#d96a80", "#b84a62", "#9c3a50"] },
  { name: "Honey Tulip",       shape: "tulip",   c: ["#eaa64f", "#d18434", "#b06a22"] },
  { name: "Peony Cloud",       shape: "pom",     c: ["#f2b9c6", "#e290a6", "#d17690"] },
  { name: "Marigold Puff",     shape: "pom",     c: ["#f0a83e", "#dd8b25", "#c47512"] },
  { name: "Little Sun",        shape: "sun",     c: ["#f3c141", "#e0a92b", "#7a5230"] },
  { name: "Evening Poppy",     shape: "poppy",   c: ["#e2593f", "#c43e28", "#3d332a"] },
  { name: "Coral Poppy",       shape: "poppy",   c: ["#ef8a63", "#dc6b42", "#6e4534"] },
  { name: "Quiet Lavender",    shape: "spike",   c: ["#a58fc7", "#8a70b3", "#6d5596"] },
  { name: "Meadow Sage",       shape: "spike",   c: ["#7f9bd1", "#6280bb", "#4d68a3"] },
  { name: "Morning Bluebell",  shape: "bell",    c: ["#8ea6dd", "#7189c6", "#5871ad"] },
  { name: "Snowdrop Bell",     shape: "bell",    c: ["#f6f3ea", "#dcd6c6", "#b9d08b"] },
  { name: "Star Lily",         shape: "star",    c: ["#f4e9f2", "#e3c8de", "#d9a441"] },
  { name: "Apricot Lily",      shape: "star",    c: ["#f4c39a", "#e8a670", "#c47512"] },
  { name: "Hydrangea Whisper", shape: "cluster", c: ["#b6c6e8", "#93a8d8", "#7b91c6"] },
  { name: "Lilac Whisper",     shape: "cluster", c: ["#cdb2dd", "#b593cc", "#9d78b8"] },
  { name: "Forget-me-not",     shape: "cluster", c: ["#9fc0e8", "#7ea7dc", "#e8b64c"] }
];

/* Planting spots inside the meadow - away from the tree (left), the pond
   (right) and the fence (back). Ordered so the garden fills prettily. */
const GARDEN_SPOTS = [
  [385, 385], [305, 400], [465, 395], [345, 355], [430, 350], [265, 370],
  [505, 360], [230, 405], [545, 400], [370, 425], [450, 425], [290, 335],
  [485, 330], [220, 340], [550, 335], [255, 425], [525, 425], [325, 315],
  [415, 312], [560, 440], [200, 380], [585, 315], [355, 300], [470, 300],
  [610, 425], [195, 315], [640, 300], [300, 300]
];

const gToday = () => new Date().toLocaleDateString("en-CA");   // YYYY-MM-DD
const r1 = v => Math.round(v * 10) / 10;

/* ---------- drawing ---------- */
function flowerHead(shape, c, r) {
  const [p, pd, ctr] = c;
  let out = "";
  if (shape === "daisy") {
    for (let i = 0; i < 9; i++)
      out += `<ellipse rx="${r * 0.34}" ry="${r}" fill="${i % 2 ? p : pd}" transform="rotate(${i * 40}) translate(0 ${-r * 0.72})"/>`;
    out += `<circle r="${r * 0.42}" fill="${ctr}"/>`;
  } else if (shape === "tulip") {
    out += `<path d="M${-r} ${r * 0.4} Q${-r} ${-r} 0 ${-r * 1.1} Q${r} ${-r} ${r} ${r * 0.4} Q${r * 0.5} ${r} 0 ${r} Q${-r * 0.5} ${r} ${-r} ${r * 0.4}Z" fill="${p}"/>`;
    out += `<path d="M${-r * 0.45} ${-r * 0.7} L${-r * 0.2} ${r * 0.6} M${r * 0.45} ${-r * 0.7} L${r * 0.2} ${r * 0.6}" stroke="${pd}" stroke-width="${r * 0.14}" fill="none" stroke-linecap="round"/>`;
  } else if (shape === "pom") {
    out += `<circle r="${r}" fill="${pd}"/><circle r="${r * 0.72}" fill="${p}" cx="${-r * 0.1}" cy="${-r * 0.12}"/><circle r="${r * 0.4}" fill="${pd}" cx="${r * 0.08}" cy="${-r * 0.05}" opacity="0.55"/><circle r="${r * 0.2}" fill="${p}"/>`;
  } else if (shape === "sun") {
    for (let i = 0; i < 12; i++)
      out += `<path d="M0 0 L${-r * 0.22} ${-r * 0.8} Q0 ${-r * 1.25} ${r * 0.22} ${-r * 0.8} Z" fill="${i % 2 ? p : pd}" transform="rotate(${i * 30})"/>`;
    out += `<circle r="${r * 0.5}" fill="${ctr}"/><circle r="${r * 0.5}" fill="none" stroke="${p}" stroke-width="${r * 0.06}" opacity="0.5"/>`;
  } else if (shape === "poppy") {
    for (let i = 0; i < 4; i++)
      out += `<circle r="${r * 0.62}" fill="${i % 2 ? p : pd}" opacity="0.92" transform="rotate(${45 + i * 90}) translate(0 ${-r * 0.42})"/>`;
    out += `<circle r="${r * 0.3}" fill="${ctr}"/>`;
  } else if (shape === "star") {
    for (let i = 0; i < 6; i++)
      out += `<ellipse rx="${r * 0.3}" ry="${r}" fill="${i % 2 ? p : pd}" transform="rotate(${i * 60}) translate(0 ${-r * 0.6})"/>`;
    out += `<circle r="${r * 0.26}" fill="${ctr}"/>`;
  } else if (shape === "cluster") {
    const pts = [[0, -r * 0.9], [-r * 0.7, -r * 0.4], [r * 0.7, -r * 0.4], [-r * 0.45, r * 0.25], [r * 0.45, r * 0.25], [0, -r * 0.15], [0, r * 0.7]];
    pts.forEach(([x, y], i) => { out += `<circle cx="${x}" cy="${y}" r="${r * 0.42}" fill="${i % 2 ? p : pd}"/>`; });
    out += `<circle r="${r * 0.14}" fill="${ctr}"/>`;
  }
  return out;
}

/* A flower at a growth stage. Drawn with its roots at (0,0), growing upward. */
function flowerSVG(f, big) {
  const sp = FLOWER_SPECIES[f.sp % FLOWER_SPECIES.length];
  const stage = f.mature || f.watered >= GROW_DAYS ? 3 : f.watered >= 5 ? 2 : f.watered >= 2 ? 1 : 0;
  const stem = "#5f8a52", leaf = "#74a15f";
  const H = [10, 20, 30, 38][stage] * (big ? 2.2 : 1);
  const r = [0, 4, 6.5, 9][stage] * (big ? 2.2 : 1);
  let g = `<path d="M0 0 Q${H * 0.08} ${-H * 0.5} 0 ${-H}" stroke="${stem}" stroke-width="${big ? 4 : 2.2}" fill="none" stroke-linecap="round"/>`;
  g += `<path d="M0 ${-H * 0.35} q${-H * 0.38} ${-H * 0.12} ${-H * 0.42} ${-H * 0.42} q${H * 0.3} ${H * 0.05} ${H * 0.42} ${H * 0.42}" fill="${leaf}"/>`;
  g += `<path d="M0 ${-H * 0.55} q${H * 0.38} ${-H * 0.1} ${H * 0.4} ${-H * 0.38} q${-H * 0.3} ${H * 0.03} ${-H * 0.4} ${H * 0.38}" fill="${leaf}"/>`;
  if (stage === 0) {
    g += `<circle cx="0" cy="${-H}" r="${big ? 5 : 2.4}" fill="${leaf}"/>`;
  } else if (stage === 1) {
    g += `<ellipse cx="0" cy="${-H - r * 0.5}" rx="${r * 0.55}" ry="${r * 0.85}" fill="${sp.c[1]}"/><path d="M${-r * 0.4} ${-H} Q0 ${-H - r * 1.4} ${r * 0.4} ${-H}" fill="${sp.c[0]}" opacity="0.7"/>`;
  } else if (sp.shape === "spike") {
    for (let i = 0; i < 6; i++)
      g += `<ellipse cx="${(i % 2 ? 1 : -1) * r * 0.28}" cy="${-H + r * 0.5 - i * r * 0.42}" rx="${r * 0.34}" ry="${r * 0.26}" fill="${i % 2 ? sp.c[0] : sp.c[1]}"/>`;
  } else if (sp.shape === "bell") {
    for (const [dx, dy] of [[-r * 0.55, 0], [r * 0.55, -r * 0.3], [0, -r * 0.7]])
      g += `<path transform="translate(${dx} ${-H + dy})" d="M${-r * 0.38} 0 Q${-r * 0.42} ${-r * 0.75} 0 ${-r * 0.75} Q${r * 0.42} ${-r * 0.75} ${r * 0.38} 0 L${r * 0.24} ${r * 0.18} L0 ${r * 0.02} L${-r * 0.24} ${r * 0.18} Z" fill="${sp.c[0]}" stroke="${sp.c[1]}" stroke-width="0.6"/>`;
  } else {
    g += `<g transform="translate(0 ${-H - r * 0.35}) rotate(${f.rot || 0})">${flowerHead(sp.shape, sp.c, r)}</g>`;
  }
  if (stage === 3 && !big) g += `<circle cx="${r * 0.9}" cy="${-H - r * 1.1}" r="1.3" fill="#fff" opacity="0.85" class="gtwinkle"/>`;
  return g;
}

/* The garden scene: warm sky, fence, tree, bushes, pond with koi, meadow. */
function gardenScene(flowersMarkup) {
  return `
<svg viewBox="0 0 900 470" class="garden-svg" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Your garden">
  <defs>
    <linearGradient id="gsky" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#e8eedd"/><stop offset="0.7" stop-color="#f6efdd"/><stop offset="1" stop-color="#f3ead5"/>
    </linearGradient>
    <linearGradient id="ggrass" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#a9c48c"/><stop offset="1" stop-color="#b8cf9c"/>
    </linearGradient>
    <radialGradient id="gpond" cx="0.5" cy="0.4" r="0.8">
      <stop offset="0" stop-color="#c2dde4"/><stop offset="0.7" stop-color="#9dc4d1"/><stop offset="1" stop-color="#83aebd"/>
    </radialGradient>
    <radialGradient id="gsun" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="#f6dfa2" stop-opacity="0.9"/><stop offset="1" stop-color="#f6dfa2" stop-opacity="0"/>
    </radialGradient>
  </defs>

  <rect width="900" height="470" fill="url(#gsky)"/>
  <circle cx="760" cy="72" r="86" fill="url(#gsun)" class="gsun"/>
  <circle cx="760" cy="72" r="30" fill="#f3d488" opacity="0.9"/>

  <g class="gcloud gcloud1" opacity="0.85">
    <ellipse cx="180" cy="70" rx="52" ry="17" fill="#fdfaf2"/><ellipse cx="220" cy="60" rx="38" ry="14" fill="#fdfaf2"/><ellipse cx="145" cy="60" rx="30" ry="12" fill="#fdfaf2"/>
  </g>
  <g class="gcloud gcloud2" opacity="0.7">
    <ellipse cx="520" cy="46" rx="44" ry="13" fill="#fdfaf2"/><ellipse cx="552" cy="38" rx="30" ry="11" fill="#fdfaf2"/>
  </g>

  <!-- meadow -->
  <path d="M0 250 Q220 225 450 240 Q700 255 900 235 L900 470 L0 470 Z" fill="url(#ggrass)"/>
  <path d="M0 300 Q300 280 900 300 L900 470 L0 470 Z" fill="#aeca92" opacity="0.6"/>

  <!-- fence along the back -->
  <g stroke="#c9a878" stroke-width="0" fill="#cfab7d">
    ${[...Array(15)].map((_, i) => `<rect x="${18 + i * 62}" y="216" width="9" height="42" rx="3"/><path d="M${18 + i * 62} 216 l4.5 -7 l4.5 7 z"/>`).join("")}
    <rect x="8" y="224" width="884" height="6" rx="3" fill="#c29c6d"/>
    <rect x="8" y="242" width="884" height="6" rx="3" fill="#c29c6d"/>
  </g>

  <!-- big tree on the left -->
  <g class="gtree">
    <path d="M96 268 Q92 210 104 178 Q110 210 112 268 Z" fill="#8a6647"/>
    <path d="M100 215 q-18 -8 -26 -24" stroke="#8a6647" stroke-width="7" fill="none" stroke-linecap="round"/>
    <ellipse cx="66" cy="168" rx="46" ry="38" fill="#7fa46f"/>
    <ellipse cx="118" cy="140" rx="56" ry="46" fill="#8db37c"/>
    <ellipse cx="160" cy="176" rx="42" ry="34" fill="#77a066"/>
    <circle cx="96" cy="150" r="4" fill="#e6a1b2"/><circle cx="132" cy="128" r="4" fill="#e6a1b2"/><circle cx="150" cy="162" r="3.4" fill="#e6a1b2"/>
  </g>

  <!-- bushes -->
  <ellipse cx="270" cy="256" rx="40" ry="18" fill="#93b47c"/>
  <ellipse cx="330" cy="260" rx="30" ry="14" fill="#a0bf89"/>
  <ellipse cx="850" cy="258" rx="46" ry="18" fill="#93b47c"/>

  <!-- pond -->
  <g>
    <ellipse cx="712" cy="368" rx="158" ry="62" fill="#8fae86"/>
    <ellipse cx="712" cy="364" rx="148" ry="55" fill="url(#gpond)"/>
    <ellipse cx="680" cy="350" rx="60" ry="16" fill="#ffffff" opacity="0.25"/>
    <ellipse class="gripple gr1" cx="712" cy="364" rx="30" ry="10" fill="none" stroke="#eaf4f6" stroke-width="1.6"/>
    <ellipse class="gripple gr2" cx="760" cy="378" rx="22" ry="8"  fill="none" stroke="#eaf4f6" stroke-width="1.4"/>
    <g class="gkoi">
      <g><ellipse rx="14" ry="5.5" fill="#e2724c"/><path d="M-13 0 L-21 -5 L-21 5 Z" fill="#e2724c"/><circle cx="7" cy="-1.5" r="1.2" fill="#3d332a"/><ellipse cx="-2" cy="0" rx="4" ry="5" fill="#fdfaf2" opacity="0.8"/>
        <animateMotion dur="17s" repeatCount="indefinite" rotate="auto" path="M640,356 C700,336 790,346 806,372 C790,394 690,392 648,378 C630,370 626,362 640,356 Z"/></g>
    </g>
    <g class="gkoi">
      <g><ellipse rx="11" ry="4.5" fill="#f0c987"/><path d="M-10 0 L-17 -4 L-17 4 Z" fill="#f0c987"/><circle cx="5.5" cy="-1.2" r="1" fill="#3d332a"/>
        <animateMotion dur="23s" repeatCount="indefinite" rotate="auto" path="M780,382 C720,398 660,388 646,368 C666,350 750,346 788,362 C800,370 798,378 780,382 Z"/></g>
    </g>
    <g transform="translate(636 340)"><ellipse rx="16" ry="6" fill="#6f9e63"/><path d="M0 0 L12 -3 L10 2 Z" fill="#f3ead5"/></g>
    <g transform="translate(792 350)"><ellipse rx="13" ry="5" fill="#6f9e63"/><g transform="translate(0 -6)">${flowerHead("star", ["#f2c7d4", "#e5a4b8", "#e8b64c"], 6)}</g></g>
  </g>

  <!-- water tank by the fence: spare water is stored here -->
  <g class="gtank" transform="translate(160 288)">
    <path d="M-25 -34 h50 v6 h-50 z" fill="#b08d5f"/>
    <path d="M-22 -28 C-24 -6 -24 6 -20 14 h40 C24 6 24 -6 22 -28 Z" fill="#c9a878"/>
    <path d="M-22 -28 C-24 -6 -24 6 -20 14 h8 C-16 6 -16 -6 -15 -28 Z" fill="#bd9a6b"/>
    <rect x="-23" y="-22" width="46" height="4" rx="2" fill="#8a6647"/>
    <rect x="-22" y="2"   width="44" height="4" rx="2" fill="#8a6647"/>
    <ellipse cx="0" cy="-31" rx="22" ry="4.5" fill="#9dc4d1"/>
    <ellipse cx="-6" cy="-32" rx="9" ry="1.8" fill="#eaf4f6" opacity="0.7" class="gtank-shimmer"/>
    <path d="M20 -6 h7 v4 h-4 v5 h-3 z" fill="#8f8a82"/>
    <circle cx="25" cy="8" r="1.6" fill="#9dc4d1" class="gtank-drip"/>
    <g transform="translate(0 -46)">
      <rect x="-26" y="-13" width="52" height="19" rx="6" fill="#fffdf8" stroke="#c9a878" stroke-width="1.6"/>
      <path d="M-13 -9 c0 3.4 -2.5 4.6 -2.5 6.8 a2.5 2.5 0 0 0 5 0 C-10.5 -4.4 -13 -5.6 -13 -9 Z" fill="#7fb0c4"/>
      <text id="gtank-count" x="6" y="1.5" text-anchor="middle" font-size="12" font-weight="700"
            fill="#6e4534" font-family="Georgia, serif">0</text>
    </g>
  </g>

  <!-- stones + grass tufts -->
  <ellipse cx="205" cy="285" rx="14" ry="7" fill="#c9c2b4"/><ellipse cx="228" cy="290" rx="9" ry="5" fill="#d6cfc0"/>
  <ellipse cx="600" cy="450" rx="16" ry="7" fill="#c9c2b4"/>
  ${[[250, 300], [430, 285], [560, 295], [180, 440], [660, 448], [90, 330], [140, 390]].map(([x, y]) =>
    `<path d="M${x} ${y} q-3 -10 -6 -12 M${x} ${y} q0 -12 1 -14 M${x} ${y} q4 -9 7 -11" stroke="#87a86e" stroke-width="2" fill="none" stroke-linecap="round"/>`).join("")}

  <!-- butterflies -->
  <g class="gbfly gb1"><g class="gwings"><ellipse cx="-4" cy="0" rx="4.5" ry="3.2" fill="#e6a1b2"/><ellipse cx="4" cy="0" rx="4.5" ry="3.2" fill="#e6a1b2"/><rect x="-0.8" y="-3" width="1.6" height="6" rx="0.8" fill="#6e4534"/></g></g>
  <g class="gbfly gb2"><g class="gwings"><ellipse cx="-4" cy="0" rx="4" ry="2.8" fill="#d9a441"/><ellipse cx="4" cy="0" rx="4" ry="2.8" fill="#d9a441"/><rect x="-0.7" y="-2.6" width="1.4" height="5.2" rx="0.7" fill="#6e4534"/></g></g>

  <!-- flowers -->
  <g id="garden-flowers">${flowersMarkup}</g>
</svg>`;
}

Object.assign(app, {
  /* ---------- garden data ---------- */
  gardenFor() {
    const map = DB.read("calmio_garden", {});
    let g = map[this.me.id];
    if (!g) {
      g = {
        start: now(), water: 1, flowers: [this._newFlower(0)],
        discovered: [], earnedDate: "", earnedToday: 0, credited: {}, wateredDate: ""
      };
      g.discovered.push(g.flowers[0].sp);
      map[this.me.id] = g;
      DB.write("calmio_garden", map);
    }
    return g;
  },
  gardenSave(g) {
    const map = DB.read("calmio_garden", {});
    map[this.me.id] = g;
    DB.write("calmio_garden", map);
  },
  _newFlower(spotIdx) {
    return {
      id: uid(), sp: Math.floor(Math.random() * FLOWER_SPECIES.length),
      rot: Math.floor(Math.random() * 21) - 10,
      spot: spotIdx % GARDEN_SPOTS.length, watered: 0, mature: false, born: now()
    };
  },
  gardenMult(g) {
    const weeks = Math.floor((now() - g.start) / (7 * 864e5));
    return Math.min(GARDEN_MAX_MULT, Math.pow(2, weeks));
  },
  gardenCap(g) { return g.flowers.length + GARDEN_CAP_BONUS; },

  /* ---------- earning: water arrives and the garden drinks by itself ---------- */
  creditWater(kind) {
    if (!this.me || this.me.role !== "student" || !GARDEN_BASE[kind]) return;
    const g = this.gardenFor();
    const t = gToday();
    if (g.credited[kind] === t) { this._autoWater(g, false); return; }
    if (g.earnedDate !== t) { g.earnedDate = t; g.earnedToday = 0; }
    const room = Math.max(0, this.gardenCap(g) - g.earnedToday);
    const amt = r1(Math.min(room, GARDEN_BASE[kind] * this.gardenMult(g)));
    g.credited[kind] = t;
    if (amt > 0) {
      g.water = r1(g.water + amt);
      g.earnedToday = r1(g.earnedToday + amt);
    }
    this.gardenSave(g);
    const st = this._autoWater(g, false);
    if (amt > 0) {
      const g2 = this.gardenFor();
      const msg =
        st === "watered" ? `+${amt} water - your flowers drank today's share. Tank: ${g2.water}.` :
        st === "already" ? `+${amt} water saved in your garden's tank (${g2.water}).` :
        `+${amt} water in the tank (${g2.water}) - ${r1(g2.flowers.length - g2.water)} more and the garden waters itself.`;
      setTimeout(() => this.toast(msg), 600);
    }
  },

  /* If today's watering hasn't happened yet and the tank holds enough,
     the garden waters itself. Returns "watered" | "already" | "short".
     quiet=true skips the re-render (used from inside renderGarden). */
  _autoWater(g, quiet) {
    const t = gToday();
    if (g.wateredDate === t) return "already";
    const need = g.flowers.length;
    if (g.water < need) return "short";
    g.water = r1(g.water - need);
    g.wateredDate = t;
    const grow = g.flowers.find(f => !f.mature);
    let bloomed = false;
    if (grow) {
      grow.watered++;
      if (grow.watered >= GROW_DAYS) { grow.mature = true; bloomed = true; }
    }
    this.gardenSave(g);
    const gardenVisible = !document.getElementById("view-garden").hidden;
    if (gardenVisible && !quiet) this.renderGarden();
    if (gardenVisible) setTimeout(() => this._waterFx(), 300);
    if (bloomed) setTimeout(() => this._awardFlower(), 1500);
    return "watered";
  },

  /* ---------- rendering ---------- */
  renderGarden() {
    const g = this.gardenFor();
    const t = gToday();
    if (g.earnedDate !== t) { g.earnedDate = t; g.earnedToday = 0; this.gardenSave(g); }
    this._autoWater(g, true);   // catch up if the tank already holds enough
    const flowers = g.flowers.map((f, i) => {
      const [x, y] = GARDEN_SPOTS[f.spot % GARDEN_SPOTS.length];
      const scale = 0.68 + Math.max(0, Math.min(1, (y - 295) / 135)) * 0.5;
      const pop = this._justPlanted === f.id ? " gpop" : "";
      return `<g transform="translate(${x} ${y}) scale(${scale.toFixed(2)})"><g class="gflower${pop}" style="animation-delay:${(i * 0.7) % 4}s">${flowerSVG(f)}</g></g>`;
    }).join("");
    this._justPlanted = null;
    document.getElementById("garden-scene").innerHTML = gardenScene(flowers);
    document.getElementById("gtank-count").textContent = g.water;

    const disc = [...new Set(g.discovered)];
    document.getElementById("garden-collection").innerHTML =
      `<p class="tiny">${disc.length} of ${FLOWER_SPECIES.length} kinds</p>` +
      `<div class="coll-grid">` + FLOWER_SPECIES.map((sp, i) => disc.includes(i)
        ? `<div class="coll-item" title="${sp.name}"><svg viewBox="-16 -46 32 50">${flowerSVG({ sp: i, watered: GROW_DAYS, rot: 0 })}</svg><span>${sp.name}</span></div>`
        : `<div class="coll-item unknown"><svg viewBox="-16 -46 32 50"><text x="0" y="-14" text-anchor="middle" font-size="20" fill="#c9beac">?</text></svg><span>?</span></div>`).join("") + `</div>`;
  },

  _waterFx() {
    const wrap = document.getElementById("garden-scene");
    if (!wrap || !wrap.firstChild) return;
    const fx = document.createElement("div");
    fx.className = "water-fx";
    for (let i = 0; i < 14; i++) {
      const d = document.createElement("i");
      d.style.left = (8 + Math.random() * 84) + "%";
      d.style.animationDelay = (Math.random() * 0.7) + "s";
      fx.appendChild(d);
    }
    wrap.appendChild(fx);
    setTimeout(() => fx.remove(), 1900);
  },

  /* ---------- new-flower reveal ---------- */
  _awardFlower() {
    const g = this.gardenFor();
    const undisc = FLOWER_SPECIES.map((_, i) => i).filter(i => !g.discovered.includes(i));
    const sp = undisc.length && Math.random() < 0.8
      ? undisc[Math.floor(Math.random() * undisc.length)]
      : Math.floor(Math.random() * FLOWER_SPECIES.length);
    const f = this._newFlower(g.flowers.length);
    f.sp = sp;
    this._pendingFlower = f;
    document.getElementById("reveal-flower").innerHTML =
      `<svg viewBox="-40 -110 80 118">${flowerSVG({ ...f, watered: GROW_DAYS }, true)}</svg>`;
    document.getElementById("reveal-name").textContent = FLOWER_SPECIES[sp].name;
    document.getElementById("reveal-sub").textContent =
      "Your flower bloomed - and left you a seed of something new. It starts as a little sprout.";
    document.getElementById("reveal-backdrop").classList.add("open");
  },

  plantReveal() {
    const f = this._pendingFlower;
    if (!f) { document.getElementById("reveal-backdrop").classList.remove("open"); return; }
    this._pendingFlower = null;
    const g = this.gardenFor();
    g.flowers.push(f);
    if (!g.discovered.includes(f.sp)) g.discovered.push(f.sp);
    this.gardenSave(g);
    document.getElementById("reveal-backdrop").classList.remove("open");
    this._justPlanted = f.id;
    this.renderGarden();
    this.toast(`${FLOWER_SPECIES[f.sp].name} planted. It drinks 1 water a day like the others.`);
  }
});

/* Boot: open the encrypted vault first, then start the app */
Vault.init().then(() => app.init());
