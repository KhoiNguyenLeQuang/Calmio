/* ============================================================
   Calmio configuration
   ------------------------------------------------------------
   LOCAL MODE (default): leave url/anonKey empty. Everything runs
   in this browser only - good for demos.

   MULTI-USER MODE: create a Supabase project, run
   supabase-schema.sql in its SQL editor, then paste the two
   values from Project Settings -> API here and redeploy.
   The anon key is PUBLIC by design (safe to commit) - all real
   protection is Row Level Security in the database.
   ============================================================ */
window.CALMIO_REMOTE = {
  url: "https://mgjbahhmvteakzpvfepq.supabase.co",        // e.g. "https://abcdefghijk.supabase.co"
  anonKey: "sb_publishable_N6HWYi2qxa31kA7To6nxMw_akfqt-fQ"     // the long "anon / public" key
};
