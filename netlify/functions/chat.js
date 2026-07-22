/* Calmio AI helper endpoint.
 *
 * Deploy this with the site on Netlify and set the environment variable
 * ANTHROPIC_API_KEY in Site settings -> Environment variables.
 * The key lives ONLY here on the server - never in the site's JavaScript.
 *
 * The front end calls POST /api/chat with { "message": "..." } and
 * expects { "reply": "..." } back. If this function is not deployed,
 * the site quietly falls back to its built-in demo replies.
 */

const SYSTEM_PROMPT = `You are a thinking partner for TEACHERS at a school,
inside a student mental-health app called Calmio. A teacher describes a
situation with a student and you help them think it through.

Rules:
- Be warm, concise (under 180 words), and practical.
- Offer balanced perspective; never simply agree. If a proposed action is
  a bad idea (e.g. "should I make the test easier for everyone?"), say so
  kindly and suggest better options.
- For anything involving self-harm, suicide, abuse, or safety, tell the
  teacher clearly to involve the school counselor / crisis team TODAY and
  not to promise the student secrecy. Do not provide crisis counseling
  yourself.
- Never diagnose a student. Never suggest medication.
- Remind the teacher, when relevant, that the school counselor's judgment
  comes before any AI suggestion.`;

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: JSON.stringify({ error: "POST only" }) };
  }
  let message = "";
  try { message = (JSON.parse(event.body || "{}").message || "").toString(); }
  catch { /* fall through to the length check */ }
  if (!message.trim() || message.length > 2000) {
    return { statusCode: 400, body: JSON.stringify({ error: "Send { message } up to 2000 chars" }) };
  }
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) {
    return { statusCode: 500, body: JSON.stringify({ error: "ANTHROPIC_API_KEY is not configured" }) };
  }
  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-6",
        max_tokens: 500,
        system: SYSTEM_PROMPT,
        messages: [{ role: "user", content: message }]
      })
    });
    const data = await res.json();
    const reply = (data.content || []).map(c => c.text || "").join("\n").trim();
    if (!reply) throw new Error("empty reply");
    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reply })
    };
  } catch (e) {
    return { statusCode: 502, body: JSON.stringify({ error: "AI request failed" }) };
  }
};
