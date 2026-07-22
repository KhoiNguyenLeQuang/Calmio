-- =====================================================================
-- Calmio - Supabase schema, Row Level Security, and helper functions
-- ---------------------------------------------------------------------
-- Paste this WHOLE file into your Supabase project's SQL editor and run
-- it once. It matches js/remote.js exactly.
--
-- Shape: every app record is stored as-is in a jsonb `data` column,
-- plus the few typed columns Row Level Security needs (author, role...).
-- Security lives HERE, in the database - the browser is never trusted.
--
-- Roles: student / teacher (counselor) / admin.
-- Public sign-up can only ever create students. Staff accounts are made
-- by the admin UI through a server function using the service-role key.
-- =====================================================================

-- ---------- profiles: one per auth user ----------
create table public.profiles (
  id         uuid primary key references auth.users on delete cascade,
  username   text unique not null check (username ~ '^[a-z0-9][a-z0-9._-]{2,19}$'),
  email      text,
  display    text not null default '',
  role       text not null default 'student' check (role in ('student','teacher','admin')),
  anon_code  text unique,               -- e.g. student4271 (stable code name for anonymous messages)
  profile    jsonb not null default '{}'::jsonb,   -- fullName, nickname, dob, school, className, hobbies, clubs, photo
  updated_at timestamptz not null default now()
);

-- Auto-create a profile on sign-up (metadata comes from the sign-up form).
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, username, email, display, profile, anon_code)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'username', 'user_' || left(new.id::text, 8)),
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', ''),
    jsonb_build_object(
      'fullName', coalesce(new.raw_user_meta_data->>'full_name', ''),
      'school',   coalesce(new.raw_user_meta_data->>'school', '')
    ),
    'student' || lpad((floor(random() * 9000) + 1000)::int::text, 4, '0')
  );
  return new;
end $$;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Current user's role (used by policies below)
create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as
$$ select role from public.profiles where id = auth.uid() $$;

-- School and class are fixed once set; users can never change their own role.
create or replace function public.protect_profile_fields()
returns trigger language plpgsql as $$
begin
  if auth.uid() = old.id then
    if new.role is distinct from old.role then
      raise exception 'role can only be changed by an administrator';
    end if;
    if coalesce(old.profile->>'school','') <> ''
       and coalesce(new.profile->>'school','') is distinct from coalesce(old.profile->>'school','') then
      raise exception 'school is fixed once set';
    end if;
    if coalesce(old.profile->>'className','') <> ''
       and coalesce(new.profile->>'className','') is distinct from coalesce(old.profile->>'className','') then
      raise exception 'class is fixed once set';
    end if;
  end if;
  new.updated_at := now();
  return new;
end $$;
create trigger profiles_protect before update on public.profiles
  for each row execute function public.protect_profile_fields();

alter table public.profiles enable row level security;
create policy "own profile"              on public.profiles for select using (id = auth.uid());
create policy "staff read all"           on public.profiles for select using (public.my_role() in ('teacher','admin'));
create policy "everyone sees counselors" on public.profiles for select using (role = 'teacher'); -- students need the counselor list
create policy "update own profile"       on public.profiles for update using (id = auth.uid());

-- Pre-auth helpers (SECURITY DEFINER so they work before sign-in).
-- Note: these let anyone check whether a username exists - unavoidable
-- with unique public usernames. Password guessing is rate-limited by
-- Supabase Auth itself.
create or replace function public.email_for_username(u text) returns text
language sql stable security definer set search_path = public as
$$ select email from public.profiles where username = lower(u) $$;

create or replace function public.username_taken(u text) returns boolean
language sql stable security definer set search_path = public as
$$ select exists (select 1 from public.profiles where username = lower(u)) $$;

grant execute on function public.email_for_username(text) to anon, authenticated;
grant execute on function public.username_taken(text)     to anon, authenticated;

-- ---------- thoughts (journal entries; replies live inside data) ----------
create table public.thoughts (
  id         text primary key,
  author     uuid not null references public.profiles(id) on delete cascade,
  anonymous  boolean not null default false,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.thoughts enable row level security;
create policy "students write own"     on public.thoughts for insert with check (author = auth.uid());
create policy "author reads own"       on public.thoughts for select using (author = auth.uid());
create policy "staff read all"         on public.thoughts for select using (public.my_role() in ('teacher','admin'));
create policy "author updates own"     on public.thoughts for update using (author = auth.uid());
create policy "staff update (replies)" on public.thoughts for update using (public.my_role() in ('teacher','admin'));
-- Anonymity note: rows carry the author id so students keep access to
-- their own threads; the front-end shows profiles.anon_code instead of a
-- name when anonymous = true. A counselor with database access could
-- resolve identity; if you need stronger guarantees, move identity into
-- a table only service functions can join.

-- ---------- appreciation notes ----------
create table public.loves (
  id         text primary key,
  author     uuid references public.profiles(id) on delete cascade,
  to_id      uuid,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.loves enable row level security;
create policy "send love"       on public.loves for insert with check (author = auth.uid());
create policy "recipient reads" on public.loves for select using (to_id = auth.uid() or author = auth.uid());
create policy "staff read all"  on public.loves for select using (public.my_role() in ('teacher','admin'));

-- ---------- articles ----------
create table public.articles (
  id         text primary key,
  author     uuid references public.profiles(id) on delete set null,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.articles enable row level security;
create policy "everyone reads" on public.articles for select using (auth.role() = 'authenticated');
create policy "staff publish"  on public.articles for insert with check (public.my_role() in ('teacher','admin'));
create policy "staff edit"     on public.articles for update using (public.my_role() in ('teacher','admin'));
create policy "staff delete"   on public.articles for delete using (public.my_role() in ('teacher','admin'));

-- ---------- bookings (counseling sessions) ----------
create table public.bookings (
  id         text primary key,
  teacher_id uuid not null references public.profiles(id) on delete cascade,
  booked_by  uuid references public.profiles(id) on delete cascade,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.bookings enable row level security;
create policy "student books"     on public.bookings for insert with check (booked_by = auth.uid());
create policy "participants read" on public.bookings for select using (booked_by = auth.uid() or teacher_id = auth.uid());
create policy "staff read all"    on public.bookings for select using (public.my_role() in ('teacher','admin'));
create policy "student cancels"   on public.bookings for delete using (booked_by = auth.uid());
create policy "counselor cancels" on public.bookings for delete using (teacher_id = auth.uid());

-- Students only ever learn WHICH hours are busy, never who booked them:
create or replace function public.busy_slots()
returns table (teacher_id uuid, start bigint)
language sql stable security definer set search_path = public as
$$ select teacher_id, (data->>'start')::bigint from public.bookings $$;
grant execute on function public.busy_slots() to authenticated;

-- ---------- counselor progress notes (map: key -> array of notes) ----------
create table public.notes (
  key        text primary key,          -- 'user:<uuid>' or 'anon:<uuid>'
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.notes enable row level security;
create policy "staff only" on public.notes for all
  using (public.my_role() in ('teacher','admin'))
  with check (public.my_role() in ('teacher','admin'));

-- ---------- testimonials ("People we have helped") ----------
create table public.testimonials (
  id         text primary key,
  author     uuid references public.profiles(id) on delete set null,  -- survives account deletion
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.testimonials enable row level security;
create policy "everyone reads" on public.testimonials for select using (auth.role() = 'authenticated');
create policy "own insert"     on public.testimonials for insert with check (author = auth.uid());
create policy "admin prunes"   on public.testimonials for delete using (public.my_role() = 'admin');

-- ---------- exit feedback (always kept privately) ----------
create table public.feedback (
  id         text primary key,
  author     uuid references public.profiles(id) on delete set null,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.feedback enable row level security;
create policy "own insert" on public.feedback for insert with check (author = auth.uid());
create policy "staff read" on public.feedback for select using (public.my_role() in ('teacher','admin'));

-- ---------- problem reports (the round button; works signed-out too) ----------
create table public.reports (
  id         text primary key,
  author     uuid references public.profiles(id) on delete set null,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.reports enable row level security;
create policy "anyone reports" on public.reports for insert to anon, authenticated with check (true);
create policy "admin reads"    on public.reports for select using (public.my_role() = 'admin');
create policy "admin resolves" on public.reports for delete using (public.my_role() = 'admin');

-- ---------- school settings (single row) ----------
create table public.app_settings (
  key        text primary key default 'main',
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.app_settings enable row level security;
create policy "everyone reads" on public.app_settings for select using (auth.role() = 'authenticated');
create policy "admin writes"   on public.app_settings for insert with check (public.my_role() = 'admin');
create policy "admin updates"  on public.app_settings for update using (public.my_role() = 'admin');

-- ---------- gardens (one row per student) ----------
create table public.gardens (
  id         uuid primary key references public.profiles(id) on delete cascade,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.gardens enable row level security;
create policy "own garden" on public.gardens for all
  using (id = auth.uid()) with check (id = auth.uid());

-- =====================================================================
-- AFTER RUNNING THIS FILE:
--
-- 1. Sign up your own account normally on the website, then make it the
--    first administrator by running (replace the username):
--
--      update public.profiles set role = 'admin' where username = 'your.username';
--
-- 2. (Recommended for a school-managed rollout) Authentication ->
--    Providers -> Email: turn OFF "Confirm email" so students can sign
--    in immediately. Leave it ON if you prefer email verification - the
--    sign-up form handles both cases.
--
-- 3. Every further staff account is created inside the app:
--    School settings -> Team accounts (this calls the /api/staff
--    function, which uses the service-role key on the server).
-- =====================================================================
