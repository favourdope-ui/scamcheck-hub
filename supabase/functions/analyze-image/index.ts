const allowedOrigin = "https://scamcheck-hub.vercel.app";
const corsHeaders = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Vary": "Origin",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
};
function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders });
}
const allowedMime = new Set(["image/jpeg", "image/png", "image/webp"]);
Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin");
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (origin && origin !== allowedOrigin) return json({ error: "Origin not allowed." }, 403);
  if (req.method !== "POST") return json({ error: "Use POST." }, 405);

  const apiKey = Deno.env.get("GEMINI_API_KEY");
  if (!apiKey) return json({
    error: "AI image analysis is not activated yet. Add the GEMINI_API_KEY secret to this Supabase project's Edge Function secrets.",
    code: "AI_PROVIDER_NOT_CONFIGURED"
  }, 503);

  let body: { imageBase64?: unknown; mimeType?: unknown; context?: unknown };
  try { body = await req.json(); } catch { return json({ error: "Send a valid JSON body." }, 400); }
  if (typeof body.imageBase64 !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(body.imageBase64)) {
    return json({ error: "Image data is missing or invalid." }, 400);
  }
  if (body.imageBase64.length > 5_600_000) return json({ error: "Image is too large. Please use an image under 4 MB." }, 413);
  const mimeType = typeof body.mimeType === "string" && allowedMime.has(body.mimeType) ? body.mimeType : "";
  if (!mimeType) return json({ error: "Use a JPEG, PNG, or WebP image." }, 415);
  const context = typeof body.context === "string" ? body.context.slice(0, 1500) : "";

  const prompt = `You are ScamCheck Hub's evidence-first scam-risk analyst. Examine the supplied screenshot/image itself, read visible text where possible, interpret the interface and claims, and reason about concrete scam indicators. The user may add context: ${context || "No additional context supplied."}

Return ONLY valid JSON with this exact shape:
{
 "riskScore": integer 0-100,
 "riskLevel": "High"|"Elevated"|"Lower"|"Unclear",
 "summary": string,
 "whatIsVisible": string[],
 "findings": [{"title":string,"evidence":string,"whyItMatters":string,"severity":"high"|"medium"|"low"}],
 "recommendedActions": string[],
 "confidence": "high"|"medium"|"low",
 "limitations": string[]
}

Rules:
- Distinguish what is directly visible from inference. Quote or describe specific visible evidence.
- Consider fake balances, unrealistic investment returns, deposit/withdrawal traps, advance fees, fake dashboards, urgency, impersonation, suspicious contact details, QR codes, wallet addresses, and requests for credentials.
- A polished design, large balance, or unfamiliar brand alone is not proof of fraud. Never claim a website, person, company, or transaction is confirmed fraudulent without independently verifiable evidence.
- If the image is not a scam-related screenshot, say what it appears to show and set riskLevel to Unclear or Lower as appropriate.
- Do not invent OCR text, domains, company records, matching images, or external checks. This model call does not browse the web or verify a company.
- If text is unreadable, say so. If evidence is insufficient, use a lower confidence and explain why.
- Give practical safety advice. Never ask the user to expose passwords, one-time codes, private keys, or recovery phrases.
- Scores are preliminary risk signals, not probabilities or proof.`;

  try {
    const response = await fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [
          { inlineData: { mimeType, data: body.imageBase64 } },
          { text: prompt }
        ]}],
        generationConfig: { temperature: 0.2, responseMimeType: "application/json" }
      }),
      signal: AbortSignal.timeout(45000)
    });
    const providerData = await response.json();
    if (!response.ok) {
      console.error("Gemini provider error:", response.status, providerData?.error?.status || "unknown");
      return json({ error: response.status === 429
        ? "The AI provider is temporarily rate-limited. Please try again later."
        : "The AI image-analysis provider could not complete this request. Check the Gemini API key, API activation, and quota." }, 502);
    }
    const raw = providerData?.candidates?.[0]?.content?.parts?.map((p: {text?: string}) => p.text || "").join("").trim();
    if (!raw) return json({ error: "The AI provider returned no readable analysis. Please try another image." }, 502);
    let result: any;
    try { result = JSON.parse(raw); } catch {
      const cleaned = raw.replace(/^\`\`\`json\s*/i, "").replace(/\`\`\`$/, "");
      try { result = JSON.parse(cleaned); } catch { return json({ error: "The AI response could not be validated. Please try again." }, 502); }
    }
    const score = Number.isFinite(Number(result.riskScore)) ? Math.max(0, Math.min(100, Math.round(Number(result.riskScore)))) : 0;
    const validLevels = ["High", "Elevated", "Lower", "Unclear"];
    const riskLevel = validLevels.includes(result.riskLevel) ? result.riskLevel : (score >= 65 ? "High" : score >= 30 ? "Elevated" : "Lower");
    const cleanList = (value: unknown) => Array.isArray(value) ? value.filter((x) => typeof x === "string").slice(0, 8).map((x: string) => x.slice(0, 500)) : [];
    const findings = Array.isArray(result.findings) ? result.findings.slice(0, 8).map((f: any) => ({
      title: String(f?.title || "Potential warning sign").slice(0, 120),
      evidence: String(f?.evidence || "").slice(0, 500),
      whyItMatters: String(f?.whyItMatters || "").slice(0, 500),
      severity: ["high", "medium", "low"].includes(f?.severity) ? f.severity : "low"
    })) : [];
    return json({
      provider: "Google Gemini 2.5 Flash",
      model: "gemini-2.5-flash",
      riskScore: score,
      riskLevel,
      summary: String(result.summary || "The image was analysed, but the model provided no summary.").slice(0, 1200),
      whatIsVisible: cleanList(result.whatIsVisible),
      findings,
      recommendedActions: cleanList(result.recommendedActions),
      confidence: ["high", "medium", "low"].includes(result.confidence) ? result.confidence : "low",
      limitations: cleanList(result.limitations),
      checkedAt: new Date().toISOString(),
      disclaimer: "AI-generated preliminary risk analysis, not proof of fraud or a guarantee that something is safe. Independently verify important claims."
    });
  } catch (error) {
    console.error("Gemini image analysis request failed:", error instanceof Error ? error.message : "unknown");
    return json({ error: "AI image analysis timed out or the provider could not be reached. Please try again." }, 504);
  }
});