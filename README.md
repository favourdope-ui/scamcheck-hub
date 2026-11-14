# ScamCheck Hub

ScamCheck Hub is a public beta web application for checking suspicious messages, reporting suspected scams, and sharing community warnings.

## Current application features

- Responsive public website deployed through Vercel.
- Email/password registration and sign-in through Supabase Auth, including password recovery.
- Message checks using transparent server-side warning-sign rules.
- Optional URL reputation checks through Google Web Risk when the server-side `GOOGLE_WEBRISK_API_KEY` is configured.
- Check records store a one-way SHA-256 input fingerprint, score, risk label, and findings; the original message is not stored by the check record.
- Scam report submissions are stored as pending review. Only reports marked published are intended to appear in the public reports list.
- Community posts, comments, and likes for signed-in users.
- Local image preview and perceptual fingerprint matching against the community reference set.
- AI screenshot analysis through the Gemini 2.5 Flash multimodal model, returning visible details, evidence-based warning signs, a preliminary risk score, confidence, limitations, and recommended actions when `GEMINI_API_KEY` is configured.
- Wider-web reverse-image search through Google Cloud Vision Web Detection when `GOOGLE_CLOUD_VISION_API_KEY` is configured.
- Public usage statistics. Accuracy is deliberately shown as “Not measured” until a defensible evaluation dataset exists.
- Public Privacy Notice, Terms of Use, sitemap, and robots.txt.

## Production services

- Web: Vercel project connected to the GitHub `main` branch.
- Database, authentication, storage, and Edge Functions: Supabase project `ogagokwmckknzubidqmr`.
- Message analysis: `supabase/functions/analyze-message/`.
- Multimodal screenshot analysis: `supabase/functions/analyze-image/`.
- Wider-web image search: `supabase/functions/reverse-image-search/`.
- Database schema and policies: `supabase/migrations/`.

## Provider configuration

The message checker always has its transparent rules-based fallback. Live URL reputation checks require the `GOOGLE_WEBRISK_API_KEY` Supabase Edge Function secret.

AI screenshot analysis requires the `GEMINI_API_KEY` Supabase Edge Function secret (a Gemini API key from Google AI Studio). Wider-web image search separately requires `GOOGLE_CLOUD_VISION_API_KEY`, plus Google Cloud Vision API activation and billing. These are separate services and keys.

Provider keys must remain in server-side secrets. Never put them in `index.html`, public GitHub files, or browser storage.

## Validation and deployment

GitHub Actions checks required UI features, JavaScript syntax, both Edge Function TypeScript entrypoints, and the scam-rule regression tests. Vercel deploys website changes from `main`. Supabase Edge Functions are deployed separately; the source files in this repository must be kept in sync with the deployed functions.

## Not yet launch-complete

- No payment processor, checkout flow, or working paid subscription management. The subscriptions table alone does not provide billing.
- No in-app moderator/admin dashboard or complete report-review workflow.
- AI screenshot analysis is implemented as a deployed backend function, but it remains inactive until the secure `GEMINI_API_KEY` secret is configured and the live request is tested. The message checker remains rules-based; image AI results are preliminary and are not a validated accuracy claim.
- External provider checks remain unavailable until the required server-side provider keys and Google service configuration are activated.
- Abuse prevention, rate limits, operational support, and end-to-end testing across real devices still need final verification.

ScamCheck Hub provides warning signals, not proof that a message, account, image, or website is fraudulent or safe. Users should independently verify suspicious requests and should not submit passwords, one-time codes, wallet recovery phrases, or other confidential information.
