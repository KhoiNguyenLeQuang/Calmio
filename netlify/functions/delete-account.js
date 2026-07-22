/* Self-service account deletion.
 * Verifies the caller's token, then removes their auth user. Database
 * cascades (see supabase-schema.sql) remove the profile, thoughts,
 * bookings, garden, etc. Counselor notes are keyed by text, so they are
 * cleaned up here explicitly.
 * Env vars needed: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY.
 */
const { createClient } = require("@supabase/supabase-js");

exports.handler = async (event) => {
  if (event.httpMethod !== "POST")
    return resp(405, { error: "POST only" });

  const url = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !serviceKey)
    return resp(500, { error: "Server is missing SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY" });

  const admin = createClient(url, serviceKey, { auth: { persistSession: false } });

  const token = (event.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const { data: caller, error: authErr } = await admin.auth.getUser(token);
  if (authErr || !caller || !caller.user)
    return resp(401, { error: "Not signed in" });
  const uid = caller.user.id;

  // Counselor notes about this student (keys are plain text, no FK cascade)
  await admin.from("notes").delete().in("key", ["user:" + uid, "anon:" + uid]);

  const { error } = await admin.auth.admin.deleteUser(uid);
  if (error) return resp(400, { error: error.message });
  return resp(200, { ok: true });
};

function resp(statusCode, obj) {
  return { statusCode, headers: { "content-type": "application/json" }, body: JSON.stringify(obj) };
}
