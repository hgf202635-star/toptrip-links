// Cloudflare Pages "advanced mode" worker.
// يخدم /api/status (قراءة عامة، وكتابة بكلمة سر) وباقي الطلبات يمررها للملفات الثابتة.
//
// المطلوب في إعدادات المشروع (Settings):
//   KV binding:   STATUS          (مساحة KV)
//   Secret/Var:   ADMIN_PASSWORD  (كلمة سر لوحة التحكم)

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });

async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(text)));
  return new Uint8Array(buf);
}
async function passwordOk(given, expected) {
  if (!expected || typeof given !== "string") return false;
  const [a, b] = await Promise.all([sha256(given), sha256(expected)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
const clean = (v) => (typeof v === "string" ? v.trim().slice(0, 300) : "");

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/status") {
      if (request.method === "GET") {
        let status = { mode: "auto", reason_ar: "", reason_en: "" };
        try {
          const raw = env.STATUS ? await env.STATUS.get("status") : null;
          if (raw) status = JSON.parse(raw);
        } catch (e) {}
        return json(status);
      }

      if (request.method === "POST") {
        let body = null;
        try { body = await request.json(); } catch (e) {}
        if (!body || !(await passwordOk(body.password, env.ADMIN_PASSWORD))) {
          await new Promise((r) => setTimeout(r, 800)); // تبطيء المحاولات الخاطئة
          return json({ error: "unauthorized" }, 401);
        }
        if (!env.STATUS) return json({ error: "KV binding STATUS is missing" }, 500);

        const mode = ["auto", "open", "closed"].includes(body.mode) ? body.mode : "auto";
        const status = {
          mode,
          reason_ar: clean(body.reason_ar),
          reason_en: clean(body.reason_en),
          updated: Date.now(),
        };
        await env.STATUS.put("status", JSON.stringify(status));
        return json({ ok: true, status });
      }

      return json({ error: "method not allowed" }, 405);
    }

    return env.ASSETS.fetch(request);
  },
};
