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
  "calmio_settings", "calmio_lockouts", "calmio_notes", "calmio_reports"
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
  read(key, fallback) {
    const v = Vault.cache[key];
    if (v === undefined || v === null) return fallback;
    return JSON.parse(JSON.stringify(v));           // hand out copies, never live refs
  },
  write(key, value) {
    Vault.cache[key] = JSON.parse(JSON.stringify(value));
    Vault.persist();
  },
  remove(key) {
    delete Vault.cache[key];
    Vault.persist();
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
function lockKey(name, role) { return role + "|" + name.trim().toLowerCase(); }
function getLockout(name, role) {
  const all = DB.read("calmio_lockouts", {});
  return all[lockKey(name, role)] || { fails: 0, until: 0 };
}
function setLockout(name, role, rec) {
  const all = DB.read("calmio_lockouts", {});
  all[lockKey(name, role)] = rec;
  DB.write("calmio_lockouts", all);
}

/* Stable anonymous code name, e.g. #student4271 */
function newAnonId() {
  const used = new Set(DB.read("calmio_users", []).map(u => u.anonId).filter(Boolean));
  let id;
  do { id = "student" + String(Math.floor(1000 + Math.random() * 9000)); } while (used.has(id));
  return id;
}

/* Seed data (first visit only) */
function seed() {
  if (DB.read("calmio_users", null)) return;
  const t1 = { id: uid(), name: "Dr. Lori",     role: "teacher", profile: {} };
  const t2 = { id: uid(), name: "Mr. Hart",     role: "teacher", profile: {} };
  const t3 = { id: uid(), name: "Mrs. Speidel", role: "teacher", profile: {} };
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
  const mk = (name, profile) => ({ id: uid(), name, role: "student", profile, anonId: newAnonId() });
  const s1 = mk("Minh Anh", { fullName: "Nguyen Minh Anh", nickname: "Mia", school: "Hanoi High", className: "11A2", hobbies: "Piano, reading", clubs: "Media club" });
  const s2 = mk("Duc",      { fullName: "Tran Duc",        nickname: "",    school: "Hanoi High", className: "10B1", hobbies: "Football",       clubs: "Football team" });
  const s3 = mk("Lan",      { fullName: "Pham Lan",        nickname: "",    school: "Hanoi High", className: "12C3", hobbies: "Drawing",        clubs: "Art club" });
  const s4 = mk("Khoa",     { fullName: "Le Khoa",         nickname: "",    school: "Hanoi High", className: "11A2", hobbies: "Chess, coding",  clubs: "STEM club" });
  const s5 = mk("Thu",      { fullName: "Vu Thu",          nickname: "",    school: "Hanoi High", className: "10B2", hobbies: "Badminton",      clubs: "Charity run team" });
  const s6 = mk("Bao",      { fullName: "Ngo Bao",         nickname: "",    school: "Hanoi High", className: "12A1", hobbies: "Guitar, running",clubs: "Music club" });
  const s7 = mk("Hana",     { fullName: "Dang Hana",       nickname: "Han", school: "Hanoi High", className: "11C1", hobbies: "Volleyball",     clubs: "Student council" });
  const s8 = mk("Tuan",     { fullName: "Bui Tuan",        nickname: "",    school: "Hanoi High", className: "10A3", hobbies: "Gaming",         clubs: "" });
  const s9 = mk("Linh",     { fullName: "Hoang Linh",      nickname: "",    school: "Hanoi High", className: "12B2", hobbies: "Photography",    clubs: "Yearbook team" });
  DB.write("calmio_users", [t1, t2, t3, s1, s2, s3, s4, s5, s6, s7, s8, s9]);

  const th = (from, daysAgo, body, mood, opts = {}) => ({
    id: uid(), fromId: from.id, fromName: from.name, toId: "all",
    anonymous: !!opts.anon, urgent: !!opts.urgent, body,
    ts: now() - daysAgo * D, replies: opts.replies || [],
    mood, risk: !!opts.risk
  });
  const rep = (t, daysAgo, body) => ({ fromId: t.id, name: t.name, body, ts: now() - daysAgo * D });

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
function getSettings() {
  return DB.read("calmio_settings", {
    counselorName: "", counselorOffice: "", counselorPhone: "",
    hoursStart: 8, hoursEnd: 16
  });
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

  init() {
    seed();
    migrateData();
    // The session lives in sessionStorage only: closing the page/tab wipes it,
    // so reopening Calmio always asks you to sign in again.
    const sessionId = sessionStorage.getItem("calmio_session");
    if (sessionId) {
      this.me = DB.read("calmio_users", []).find(u => u.id === sessionId) || null;
    }
    DB.remove("calmio_session");                 // clear sessions left behind by older versions
    try { localStorage.removeItem("calmio_session"); } catch {}
    if (this.me) { this.enter(); } else { this.show("welcome"); }
    this.pickRole("student");
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
    const res = await verifyPass(this.me, pass);
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
  pickRole(role) {
    this.pendingRole = role;
    document.getElementById("role-student").classList.toggle("active", role === "student");
    document.getElementById("role-teacher").classList.toggle("active", role === "teacher");
    document.getElementById("role-admin").classList.toggle("active", role === "admin");
  },

  async login() {
    const name = document.getElementById("welcome-name").value.trim();
    const pass = document.getElementById("welcome-pass").value;
    const lockoutMsg = document.getElementById("lockout-msg");
    lockoutMsg.textContent = "";
    if (!name) { this.toast("Please enter your name first."); return; }

    // Brute-force lockout check
    const lock = getLockout(name, this.pendingRole);
    if (lock.until > now()) {
      const secs = Math.ceil((lock.until - now()) / 1000);
      lockoutMsg.textContent = `Too many wrong attempts. Sign-in for this account is paused for ${secs} more seconds.`;
      return;
    }

    const users = DB.read("calmio_users", []);
    let user = users.find(u => u.name.toLowerCase() === name.toLowerCase() && u.role === this.pendingRole);

    if (!user) {
      // New account - the password typed now becomes theirs
      if (pass.length < 6) { this.toast("Choose a password of at least 6 characters to create your account."); return; }
      const salt = newSalt();
      user = { id: uid(), name, role: this.pendingRole, salt,
               passHash: await makeHash(pass, salt), profile: {}, lockMinutes: 10 };
      if (user.role === "student") user.anonId = newAnonId();
      users.push(user);
      DB.write("calmio_users", users);
      this.toast("Account created. Welcome to Calmio.");
    } else if (!user.passHash) {
      // Pre-seeded account claiming its password on first sign-in
      if (pass.length < 6) { this.toast("Set a password of at least 6 characters for this account."); return; }
      user.salt = newSalt();
      user.passHash = await makeHash(pass, user.salt);
      user.profile = user.profile || {};
      DB.write("calmio_users", users);
      this.toast("Password set for this account.");
    } else {
      // Existing account - verify
      const res = await verifyPass(user, pass);
      if (!res.ok) {
        const fails = lock.fails + 1;
        if (fails >= LOCK_MAX_FAILS) {
          setLockout(name, this.pendingRole, { fails: 0, until: now() + LOCK_SECONDS * 1000 });
          lockoutMsg.textContent = `Wrong password ${LOCK_MAX_FAILS} times - sign-in paused for ${LOCK_SECONDS} seconds to protect this account.`;
        } else {
          setLockout(name, this.pendingRole, { fails, until: 0 });
          lockoutMsg.textContent = `Wrong password (attempt ${fails} of ${LOCK_MAX_FAILS}).`;
        }
        return;
      }
      if (res.upgraded) DB.write("calmio_users", users);   // silent PBKDF2 upgrade
      setLockout(name, this.pendingRole, { fails: 0, until: 0 });
    }

    document.getElementById("welcome-pass").value = "";
    this.me = user;
    sessionStorage.setItem("calmio_session", user.id);
    this.enter();
  },

  logout() {
    sessionStorage.removeItem("calmio_session");
    this.me = null;
    document.getElementById("topbar").hidden = true;
    this.show("welcome");
    this.renderTestimonials();
  },

  enter() {
    document.getElementById("topbar").hidden = false;
    this.renderAvatar();
    document.getElementById("whoami-name").textContent = this.me.name + " \u00b7 " + this.me.role;
    this._lastActivity = now();
    this.buildNav();
    this.backHome();
  },

  renderAvatar() {
    const el = document.getElementById("avatar");
    const p = this.me.profile || {};
    el.innerHTML = p.photo
      ? `<img src="${p.photo}" alt="" />`
      : esc(this.me.name.trim()[0].toUpperCase());
  },

  buildNav() {
    const nav = document.getElementById("mainnav");
    const links = this.me.role === "student"
      ? [["Home", "student-home"], ["Share", "share"], ["Schedule", "schedule"], ["Articles", "articles"]]
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
    this.renderReports();
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
      byName: this.me ? `${this.me.name} (${this.me.role})` : "Not signed in",
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
      "How's it going, " + (p.nickname || this.me.name) + "?";

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
      "How can I help you, " + this.me.name + "?";

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
    if (!t.anonymous) return t.fromName;
    const u = DB.read("calmio_users", []).find(x => x.id === t.fromId);
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
    (all[rec.key] = all[rec.key] || []).push({ id: uid(), byName: this.me.name, text: body, ts: now() });
    DB.write("calmio_notes", all);
    this.toast("Note added.");
    this.renderStudents();
  },

  /* ---------- scheduling (weekly calendar, no setup needed) ---------- */
  renderSchedule() {
    const sel = document.getElementById("sched-teacher");
    sel.innerHTML = this.teachers().map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join("");
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
    slots.push({ id: uid(), teacherId, teacherName: teacher ? teacher.name : "Counselor",
                 start: startMs, minutes: 60, bookedBy: this.me.id, bookedName: this.me.name });
    DB.write("calmio_slots", slots);
    this.toast("Session booked with " + (teacher ? teacher.name : "your counselor") + ".");
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
      .map(u => `<option value="${u.id}">${esc(u.name)} (${u.role})</option>`).join("");
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
      id: uid(), fromId: this.me.id, fromName: this.me.name,
      toId: "all", anonymous: document.getElementById("thought-anon").checked,
      urgent: false, body, ts: now(), replies: [],
      mood: ev.score, risk: ev.risk
    });
    DB.write("calmio_thoughts", thoughts);
    document.getElementById("thought-body").value = "";
    this.toast("Sent privately to the counseling team. Thank you for sharing.");
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
      id: uid(), toId, toName: to ? to.name : "",
      fromName: document.getElementById("love-anon").checked ? "Anonymous" : this.me.name,
      reason, ts: now()
    });
    DB.write("calmio_loves", loves);
    document.getElementById("love-reason").value = "";
    this.toast("Love sent.");
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
    t.replies.push({ fromId: this.me.id, name: this.me.name, body, ts: now() });
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
    av.innerHTML = p.photo ? `<img src="${p.photo}" alt="Your photo" />` : esc(this.me.name.trim()[0].toUpperCase());

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
    const p = this.me.profile = this.me.profile || {};
    p.fullName = document.getElementById("prof-fullname").value.trim();
    p.nickname = document.getElementById("prof-nickname").value.trim();
    p.dob = document.getElementById("prof-dob").value;
    p.hobbies = document.getElementById("prof-hobbies").value.trim();
    p.clubs = document.getElementById("prof-clubs").value.trim();
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
      const res = await verifyPass(this.me, curPass);
      if (!res.ok) { this.toast("Current password is wrong - password not changed."); return; }
      this.me.salt = newSalt();
      this.me.passHash = await makeHash(newPass, this.me.salt);
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
        name: p.nickname || this.me.name,
        photo: p.photo || null,
        rating: d.rating,
        message: d.message,
        ts: now()
      });
      DB.write("calmio_testimonials", testimonials.slice(0, 20));
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
    sessionStorage.removeItem("calmio_session");

    this.closeDelete();
    this.me = null;
    document.getElementById("topbar").hidden = true;
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
    // Counselor line appears here during school hours (set by an administrator)
    document.getElementById("crisis-counselor-slot").innerHTML = counselorLine();
  },

  sendUrgent() {
    const body = document.getElementById("em-body").value.trim();
    if (!body) { this.toast("Tell them briefly what's going on."); return; }
    const ev = evaluateMood(body);
    const thoughts = DB.read("calmio_thoughts", []);
    thoughts.push({
      id: uid(), fromId: this.me.id, fromName: this.me.name,
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
        counselorLine() +
        `<div class="crisis-line">
          <div><b>988 Suicide &amp; Crisis Lifeline</b><br /><span class="tiny">Call or text 988 - 24/7, free, confidential</span></div>
          <a class="call-btn" href="tel:988">Call 988</a>
        </div>
        <div class="crisis-line">
          <div><b>Teen Line</b> - teens helping teens<br /><span class="tiny">6-9 PM Pacific, or text TEEN to 839863</span></div>
          <a class="call-btn" href="tel:8008528336">Call Teen Line</a>
        </div>
        <div class="crisis-line">
          <div><b>Crisis Text Line</b><br /><span class="tiny">Text HOME to 741741, any time</span></div>
          <a class="call-btn" href="sms:741741&body=HOME">Text 741741</a>
        </div>
        <div class="crisis-line">
          <div><b>Immediate danger</b><br /><span class="tiny">If your safety or someone else's is at risk right now</span></div>
          <a class="call-btn" href="tel:911">Call 911</a>
        </div>`;
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
  sendChat() {
    const input = document.getElementById("chat-input");
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    this.addChat(text, "user");
    setTimeout(() => this.addChat(this.demoReply(text), "bot"), 500);
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

/* Boot: open the encrypted vault first, then start the app */
Vault.init().then(() => app.init());
