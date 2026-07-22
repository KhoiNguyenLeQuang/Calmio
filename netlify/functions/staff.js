/* Admin-only staff management (create / remove counselor & admin accounts).
 *
 * Needs two environment variables on Netlify:
 *   SUPABASE_URL               - your project URL
 *   SUPABASE_SERVICE_ROLE_KEY  - Project Settings -> API -> service_role
 * The service-role key bypasses Row Level Security, which is exactly why
 * it must only ever live here on the server.
 *
 * The caller must send their own access token; we verify it belongs to an
 * admin before doing anything.
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

  // ---- verify the caller is a signed-in admin ----
  const token = (event.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const { data: caller, error: authErr } = await admin.auth.getUser(token);
  if (authErr || !caller || !caller.user)
    return resp(401, { error: "Not signed in" });
  const { data: callerProfile } = await admin
    .from("profiles").select("role").eq("id", caller.user.id).single();
  if (!callerProfile || callerProfile.role !== "admin")
    return resp(403, { error: "Administrators only" });

  let body = {};
  try { body = JSON.parse(event.body || "{}"); } catch {}

  // ---- create a counselor / admin account ----
  if (body.action === "create") {
    const { username, email, fullname, role, password } = body;
    if (!username || !email || !fullname || !password ||
        !["teacher", "admin"].includes(role))
      return resp(400, { error: "Missing or invalid fields" });

    const { data: created, error } = await admin.auth.admin.createUser({
      email, password, email_confirm: true,
      user_metadata: { username, full_name: fullname, school: "" }
    });
    if (error) return resp(400, { error: error.message });

    // The sign-up trigger created the profile as a student; promote it.
    const { error: roleErr } = await admin
      .from("profiles").update({ role }).eq("id", created.user.id);
    if (roleErr) return resp(500, { error: roleErr.message });
    return resp(200, { ok: true, id: created.user.id });
  }

  // ---- remove a staff account ----
  if (body.action === "remove") {
    if (!body.target) return resp(400, { error: "Missing target" });
    if (body.target === caller.user.id)
      return resp(400, { error: "You can't remove your own account here." });
    const { error } = await admin.auth.admin.deleteUser(body.target);
    if (error) return resp(400, { error: error.message });
    return resp(200, { ok: true });
  }

  return resp(400, { error: "Unknown action" });
};

function resp(statusCode, obj) {
  return { statusCode, headers: { "content-type": "application/json" }, body: JSON.stringify(obj) };
}
