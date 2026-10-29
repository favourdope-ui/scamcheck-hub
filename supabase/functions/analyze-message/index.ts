import { analyzeMessage } from "./rules.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
};
function json(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: corsHeaders }); }
Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Use POST to check a message." }, 405);
  const length = Number(req.headers.get("content-length") || "0");
  if (length > 12000) return json({ error: "Message is too long. The limit is 12,000 characters." }, 413);
  let body: { message?: unknown };
  try { body = await req.json(); } catch { return json({ error: "Send a valid JSON body." }, 400); }
  if (typeof body.message !== "string" || !body.message.trim()) return json({ error: "Enter a message to check." }, 400);
  if (body.message.length > 12000) return json({ error: "Message is too long. The limit is 12,000 characters." }, 413);
  return json(analyzeMessage(body.message));
});
