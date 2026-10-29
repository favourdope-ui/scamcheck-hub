# ScamCheck Hub

ScamCheck Hub is an early-stage public beta that helps people notice common warning signs in suspicious messages and submit scam reports for moderator review.

## Current features

- Responsive single-page web app deployed through Vercel.
- Server-side rule-based message analysis through the Supabase Edge Function `analyze-message`.
- Warning categories for urgency, requests for sensitive information, advance-fee pressure, unexpected prizes, unrealistic investment promises, secrecy, suspicious link prompts, and remote-access requests.
- Check results saved to Supabase as a one-way SHA-256 input fingerprint, score, risk label, and findings when the database request succeeds.
- Up to 10 recent check summaries stored locally in the visitor's browser; original messages are not placed in this local history.
- Scam report submissions stored with status `pending`; only reports whose status is `published` can appear in the community list.
- Local image preview and fingerprint only. The selected image is not uploaded.
- Public Privacy Notice and Terms of Use pages.
- GitHub Actions validation for the page's JavaScript, Edge Function TypeScript, and required files.

## Production services

- Web: Vercel project connected to the `main` branch.
- Database and Edge Function: Supabase project `ogagokwmckknzubidqmr`.
- Edge Function source: `supabase/functions/analyze-message/index.ts`.
- Database policy source: `supabase/migrations/20261029000000_secure_public_access.sql`.

The deployed Edge Function is public and accepts POST requests containing a `message` string of up to 12,000 characters. It uses deterministic rules, not a large language model or a live threat-intelligence feed.

## Deploy and validate

The Vercel project automatically deploys changes pushed to `main`. GitHub Actions validates the page and Edge Function source on pushes and pull requests.

The SQL migration file documents the browser access policies applied to the connected Supabase project. The production migration was applied directly and verified with Supabase's security advisor.

## Important limitations

This is not yet a full commercial security product. There is no account system, account-synced history, live reverse-image search, trained AI model, external threat-intelligence feed, payment/subscription integration, or in-app moderation dashboard. There is no guarantee that a score is correct or that a message is safe. Do not submit passwords, verification codes, wallet recovery phrases, or other confidential data.

Before a broader paid launch, add a verified support/contact channel, test the complete deployed flow from a real browser, establish abuse/rate controls and moderation operations, and review the privacy/terms pages for the operator's jurisdiction.
