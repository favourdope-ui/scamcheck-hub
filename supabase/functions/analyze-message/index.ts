import { analyzeMessage } from "./rules.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://scamcheck-hub.vercel.app",
  "Vary": "Origin",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
};
function json(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: corsHeaders }); }

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin");
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (origin && origin !== "https://scamcheck-hub.vercel.app") return json({ error: "Origin not allowed." }, 403);
  if (req.method !== "POST") return json({ error: "Use POST to check a message." }, 405);
  const length = Number(req.headers.get("content-length") || "0");
  if (length > 12000) return json({ error: "Message is too long. The limit is 12,000 characters." }, 413);
  let body: { message?: unknown };
  try { body = await req.json(); } catch { return json({ error: "Send a valid JSON body." }, 400); }
  if (typeof body.message !== "string" || !body.message.trim()) return json({ error: "Enter a message to check." }, 400);
  if (body.message.length > 12000) return json({ error: "Message is too long. The limit is 12,000 characters." }, 413);

  const analysis = analyzeMessage(body.message);
  const urls = [...new Set(body.message.match(/https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi) || [])].slice(0, 3);
  const apiKey = Deno.env.get("GOOGLE_WEBRISK_API_KEY");
  const urlChecks: Array<{ url: string; checked: boolean; threats: string[]; source: string }> = [];
  if (apiKey && urls.length) {
    for (const raw of urls) {
      try {
        const normalized = raw.startsWith("www.") ? "https://" + raw : raw;
        const parsed = new URL(normalized);
        if (!["http:", "https:"].includes(parsed.protocol)) continue;
        const params = new URLSearchParams();
        params.append("threatTypes", "MALWARE");
        params.append("threatTypes", "SOCIAL_ENGINEERING");
        params.set("uri", parsed.href);
        params.set("key", apiKey);
        const response = await fetch("https://webrisk.googleapis.com/v1/uris:search?" + params.toString(), { signal: AbortSignal.timeout(7000) });
        if (!response.ok) {
          console.error("Web Risk provider returned", response.status);
          urlChecks.push({ url: parsed.origin, checked: false, threats: [], source: "Google Web Risk unavailable" });
          continue;
        }
        const data = await response.json();
        const threats = Array.isArray(data.threat) ? data.threat.map((t: string) => t.replaceAll("_", " ").toLowerCase()) : [];
        urlChecks.push({ url: parsed.origin, checked: true, threats, source: "Google Web Risk" });
        if (threats.length) {
          analysis.score = Math.min(100, analysis.score + 45);
          analysis.findings.push({ title: "External threat-intelligence match", detail: "Google Web Risk currently lists this destination for " + threats.join(" and ") + ". Do not open it or enter information.", points: 45 });
        }
      } catch {
        urlChecks.push({ url: raw.slice(0, 180), checked: false, threats: [], source: "Google Web Risk unavailable" });
      }
    }
  }
  analysis.score = Math.min(100, analysis.score);
  analysis.level = analysis.score >= 55 ? "High" : analysis.score >= 25 ? "Elevated" : "Lower";
  const providerStatus = apiKey ? (urls.length ? "google-webrisk-enabled" : "google-webrisk-enabled-no-url") : "rules-only-provider-key-required";
  return json({
    ...analysis,
    method: apiKey ? "rules-plus-google-webrisk" : "transparent-rules-provider-not-configured",
    intelligence: { provider: "Google Web Risk", status: providerStatus, urlsChecked: urlChecks.length, urlChecks },
    disclaimer: "This is a risk signal, not proof. A clean result does not establish that a message or website is safe."
  });
});
