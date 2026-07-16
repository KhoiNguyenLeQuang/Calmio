# Calmio - Digital Hub for High School Students' Mental Health

Students share what's on their mind privately with the counseling team, send
anonymous "love" notes, read teacher-curated articles, book counseling
sessions straight into a counselor's school-hours calendar, and reach
emergency help. Counselors get a shared inbox, a per-student progress page
with notes and a mood graph, an article publisher, and an AI helper page.

## What's inside

```
calmio/
├── index.html      <- every page of the app (views toggled by JavaScript)
├── css/style.css   <- all styling (warm beige "healing" palette)
├── js/app.js       <- all logic + the encrypted in-browser database
└── README.md
```

No build step, no server, no dependencies. Open `index.html` (or host the
folder anywhere static). All data lives, encrypted, in the browser.
To wipe everything: DevTools (F12) -> `localStorage.clear()` -> refresh.

## The Calmio identity

- The logo is an inline SVG mark - three concentric "breathing" circles -
  next to the lowercase wordmark **calmio.** with its signature dot.
  It appears top-left, on the welcome hero, and on the lock screen.
  It's pure SVG, so it stays crisp at any size and needs no image files.
- The interface uses **no emoji or symbol characters** anywhere. Stars,
  arrows, and icons are all drawn as small inline SVGs.
- Palette: linen beige background, espresso text, cacao-brown actions,
  dusty-rose accents; Fraunces serif for display text.

## Accounts and the account manager

- Top-right corner shows the signed-in person: avatar, "Name - role", and
  a **Sign out** link.
- **Clicking the avatar opens the account manager** (there is no Settings
  tab in the navigation). It holds: profile photo, full name, nickname,
  date of birth, school, class, interests, clubs, the security controls,
  and the delete-account button.
- **School and class can be set only once.** After saving they are locked
  ("fixed" pill) and can't be edited.

## Emergency support

The Emergency tab was removed from the students' navigation. The safety
net still runs underneath: any message matching a risky pattern triggers
the gentle check-in overlay with crisis lines, and counselors see those
messages flagged "At risk". The emergency page itself still exists in
`index.html` (`view-emergency`) if you ever want to link it again.

## Booking a session (no availability forms)

Counselors are in school during working hours, so **every school hour
without a session is automatically free** - counselors never fill in
open-hours forms.

- Students open **Schedule**, pick a counselor, and see a **weekly
  calendar** (Monday-Friday, one cell per school hour). Arrows move to the
  previous/next week.
- A real bordered table: free hours are white, hours booked by someone
  else are dark gray, your own booking is highlighted, past/too-soon hours
  are hatched, and weekend columns are dark (the school is closed).
- Responsive: tablets and computers show the full 7-day week; on phones
  only Monday-Friday fits, so the weekend columns are hidden there.
  (outside school hours or in the past).
- A free hour can be booked **up to 30 minutes before it starts**
  (`BOOK_CUTOFF_MS` in `js/app.js`).
- School hours default to 8:00-16:00 and are set by the Administrator
  (School settings page).
- Every booked session has an **Add to Google Calendar** button for both
  sides - it opens a pre-filled Google Calendar event using Google's
  official template URL, so no API key or Google integration is needed.

## The Students tab (counselors)

Everything students share goes to the whole counseling team and lands in
one place: the **Students** tab. Each student is a small page; counselors
move between pages with the arrow buttons or by typing a name in the
search box.

Each student page shows:

- **AI evaluation** - a heuristic in `js/app.js` (`evaluateMood`) scores
  each message (English + Vietnamese keyword lists, plus the crisis-pattern
  scanner) and summarizes the student's current state and whether
  counseling looks needed: *Doing well / Mixed / Having a hard time /
  Struggling / At risk*.
- **A mood graph over time** - an SVG line chart of the score of every
  message the student has sent.
- **The full message history**, with reply access.
- **Progress notes** - private notes visible to counselors only, so the
  whole team can follow the student's progress up to now.
- Their booked sessions.

**Anonymity:** if a student ticks "Send as anonymous", counselors see a
stable code name - `#student` + 4 digits (e.g. `#student8712`) - instead
of their name, *everywhere*: the inbox, the Students tab, and the graph.
The code is stable per student, so a counselor can still follow one
anonymous student's progress over weeks without ever learning who they
are. Messages sent non-anonymously appear under the student's real name
as a separate page.

> The evaluation is a keyword heuristic, not a real model - good enough to
> triage in a demo, but a real deployment should route messages through a
> proper model server-side (see "AI Helper" below) and must never treat
> the score as a diagnosis. The crisis scanner always wins: any risky
> pattern marks the student "At risk" regardless of score.

## Security: what happens if someone breaks in

The threat model here is someone getting their hands on the browser's
stored data (a shared or stolen computer, another user snooping through
DevTools, malware copying files). Calmio's answer:

- **Everything is encrypted at rest.** All app data - profiles, messages,
  notes, bookings, feedback - lives in a single AES-256-GCM encrypted blob
  (`calmio_vault`). Anyone who opens localStorage sees only ciphertext.
  The encryption key is generated by the browser as **non-extractable**
  (Web Crypto) and kept in IndexedDB, so scripts - including Calmio's own
  code - can use it but never read or export the raw key bytes.
- **Passwords are never stored.** Only a salted **PBKDF2-SHA256 hash
  (150,000 iterations)** is kept; it cannot be reversed into the password.
  Older SHA-256 hashes are upgraded to PBKDF2 automatically on the next
  successful sign-in.
- **Brute-force lockout** - 5 wrong attempts pauses sign-in for that
  account for 60 seconds.
- **Auto-lock** - Calmio locks itself after N minutes of inactivity
  (default 10, adjustable 1-60 in the account manager) and requires the
  password to continue.
- **XSS protection** - everything anyone types is HTML-escaped before
  display, and a strict **Content Security Policy** in `index.html` blocks
  foreign scripts and forbids the page from sending data to any other
  domain - the two ways attackers usually inject code and exfiltrate data.
- **Password change** requires the current password.
- **Sessions end with the page.** Signing in is kept only in
  `sessionStorage`, so closing the tab or browser signs you out
  completely - reopening Calmio always asks for the password again.
  The sign-in form is a real form with proper `autocomplete`
  attributes, so browser and phone password managers can save and
  autofill credentials.

**Honest limits:** this is still a front-end-only app. Client-side
encryption raises the bar a lot (casual snooping and data-file theft get
nothing readable), but someone with full control of the same browser
profile could run code in the page's own context. Real multi-user
protection needs a server: HTTPS, server-side bcrypt/argon2, sessions,
and per-role access control - see "Going real" below.

## Delete account + "People we have helped"

The delete button sits at the bottom of the account manager. Leaving asks:

1. a reason, a star rating, and a few words, then
2. permission to show those words + photo + nickname publicly.

A testimonial appears in **People we have helped** (on the student home page) only when
*all three* hold: permission given, a full **5-star** rating, and the
message passes a kind-words check (minimum length, no negative words in
English or Vietnamese - `NEGATIVE_WORDS` in `js/app.js`). All feedback,
positive or not, is kept privately in the vault so the school can learn
from it. Deleting removes the account, profile, messages, notes about the
student, and frees their booked hours.

## Crisis safety net

Messages are scanned (English + Vietnamese patterns) for signs of self-harm
risk. A match triggers a gentle check-in with one question and, if needed,
crisis lines. The scan errs on the side of checking in; missing a real
crisis is worse than an occasional unnecessary check-in.

**The crisis numbers are US defaults (988, 741741, 911).** Administrators
in Vietnam or elsewhere must replace them with local hotlines in
`index.html` and `js/app.js` before real use.

## The Administrator role

Log in as an **Administrator** to set the school counselor's name, office
location and phone (shown on the Emergency page during school hours), and
the **school hours**, which decide exactly which hours appear as bookable
in every counselor's weekly calendar.

## The AI Helper is in demo mode

Replies come from a small built-in script (`demoReply` in `js/app.js`).
To connect a real model:

1. **Never put an API key in this project's files** - anyone can read the
   JavaScript of a website.
2. Create a serverless function (free on Netlify or Vercel) that holds the
   key as an environment variable and forwards the request.
3. Replace the `demoReply` call in `app.js` with a `fetch("/api/chat", ...)`
   to your function. The same route can replace `evaluateMood` for real
   message triage.

## Demo accounts

Three counselors are pre-seeded (Dr. Lori, Mr. Hart, Mrs. Speidel) with no
password - whoever signs in with one of those names first sets its
password. **Remove the `seed()` call in `js/app.js` before real use.**

## Privacy policy and problem reports

- Every page ends with a small footer containing an **"Our privacy policy"**
  link. It opens as an overlay, not a separate tab or page; the text lives
  in `index.html` (`privacy-backdrop`) - edit it to match your school's
  actual policy before real use.
- A round **report button** sits fixed in the bottom-right corner of every
  page. Anyone - signed in or not - can describe a problem with the
  website; reports land in the administrator's **Problem reports** card,
  where they can be marked as resolved.

## Demo students

The first run seeds **nine synthetic students** (Minh Anh, Duc, Lan, Khoa, Thu,
Bao, Hana, Tuan, Linh) with varied message histories - improving, declining,
thriving, up-and-down, a long recovery arc, and one flat/guarded case -
plus counselor replies and progress notes so the teachers' **Students** tab has something to show.
One of them writes anonymously, demonstrating the stable `#studentXXXX`
code name and how a declining trend gets flagged by the AI evaluation.
**Delete the synthetic block in `seed()` (`js/app.js`) before real use.**

## Going real (multi-user)

localStorage means each browser holds its own copy of the data - people on
different devices can't see each other's messages or bookings yet. True
multi-user needs a small backend (Supabase, Firebase, or a simple server)
with a real database, server-side password hashing (bcrypt/argon2), HTTPS,
sessions, and role-based access control. The front-end is structured so
each `DB.read`/`DB.write` call can be swapped for an API call later.
