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
  if (req.method !== "POST") return json({ error: "Use POST." }, 405);
  const apiKey = Deno.env.get("GOOGLE_CLOUD_VISION_API_KEY");
  if (!apiKey) return json({ error: "Global reverse-image search is prepared but not activated. Google Cloud Vision API credentials must be added to the secure server secrets first.", code: "PROVIDER_NOT_CONFIGURED" }, 503);
  let body: { imageBase64?: unknown; mimeType?: unknown };
  try { body = await req.json(); } catch { return json({ error: "Send a valid JSON body." }, 400); }
  if (typeof body.imageBase64 !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(body.imageBase64)) return json({ error: "Image data is missing or invalid." }, 400);
  if (body.imageBase64.length > 5_600_000) return json({ error: "Image is too large. Use an image smaller than 4 MB." }, 413);
  const mime = typeof body.mimeType === "string" && ["image/jpeg","image/png","image/webp","image/gif"].includes(body.mimeType) ? body.mimeType : "image/jpeg";
  try {
    const response = await fetch("https://vision.googleapis.com/v1/images:annotate?key=" + encodeURIComponent(apiKey), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ requests: [{ image: { content: body.imageBase64 }, features: [{ type: "WEB_DETECTION", maxResults: 12 }] }] }),
      signal: AbortSignal.timeout(20000)
    });
    const data = await response.json();
    if (!response.ok || data.responses?.[0]?.error) {
      console.error("Vision provider error", response.status);
      return json({ error: "The global image-search provider could not complete this request. Check the Google Cloud API key, billing and API activation." }, 502);
    }
    const web = data.responses?.[0]?.webDetection || {};
    const pick = (items: any[] = []) => items.slice(0, 8).map(x => ({ url: x.url, score: x.score ?? null }));
    return json({
      provider: "Google Cloud Vision Web Detection",
      bestGuessLabels: (web.bestGuessLabels || []).slice(0, 5).map((x: any) => x.label),
      webEntities: (web.webEntities || []).filter((x: any) => x.description).slice(0, 8).map((x: any) => ({ description: x.description, score: x.score ?? null })),
      matchingPages: pick(web.pagesWithMatchingImages),
      fullMatches: pick(web.fullMatchingImages),
      partialMatches: pick(web.partialMatchingImages),
      visuallySimilarImages: pick(web.visuallySimilarImages),
      disclaimer: "Search results identify possible web references or visual similarities. They do not identify a person or prove fraud."
    });
  } catch {
    return json({ error: "Global image search timed out or the provider could not be reached. Please try again." }, 504);
  }
});
