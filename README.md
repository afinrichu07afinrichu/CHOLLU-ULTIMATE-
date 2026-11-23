# CHOLLU — Cloudflare Workers development package

This package extends the uploaded CHOLLU application and includes a 4 GiB-configured R2 multipart chat attachment flow, Stories/Reels URL-based foundations, a basic admin page, a Stripe Checkout endpoint, a device registry and E2EE public-key directory endpoints.

**Important:** This is a development build, not a production-ready social network. End-to-end encryption is NOT active; group calls are NOT implemented; multi-device sync is NOT complete; Stories/Reels currently accept public HTTPS media URLs only; Premium payments must not be enabled until Stripe webhooks and entitlements are implemented. See `FEATURE_STATUS.md`.

## Cloudflare deployment

1. Extract this ZIP.
2. Upload the contents of the `CHOLLU_ULTIMATE` folder to a GitHub repository.
3. Create a Cloudflare D1 database named `chollu-db`.
4. Put the real D1 `database_id` into `wrangler.jsonc` (replace `REPLACE_WITH_YOUR_D1_DATABASE_ID`).
5. Create a Cloudflare R2 bucket named `chollu-files`. The Worker binding `BUCKET` is already in `wrangler.jsonc`.
6. Connect the GitHub repository to Cloudflare Workers.
7. Build command: leave blank / `None`.
8. Deploy command: `npx wrangler deploy`.

Local CLI alternative:

```bash
npm install
npx wrangler d1 migrations apply chollu-db --remote
npx wrangler deploy
```

### Database migration

- New empty D1 database: apply migrations `0001_initial.sql` and `0002_social_storage_devices.sql` in order.
- Existing CHOLLU database that already has migration 0001: back it up, then apply only migration 0002.
- Do not rerun 0001 against an existing populated database.

## Worker bindings and secrets

- D1: `DB`.
- R2: `BUCKET` → `chollu-files`.
- Workers AI: optional `AI` binding for the existing AI assistant.
- Push: `VAPID_PUB` (text), `VAPID_JWK` (secret), optional `VAPID_SUB` (text). Generate a fresh VAPID pair. A private key was present in an earlier upload and is considered exposed; rotate it. Never commit private keys to GitHub.
- Password reset email: `RESEND_KEY` (secret), `MAIL_FROM` (text).
- Calls: `TURN_URL`, `TURN_USER`, `TURN_CRED` (optional for one-to-one calls; TURN is recommended).
- Admin: `ADMIN_USER_IDS` (comma-separated numeric user IDs). Only trusted administrator IDs should be included.
- Premium checkout: `STRIPE_SECRET_KEY` (secret), `STRIPE_PRICE_ID` (text). Do not accept payments until webhook verification and subscription entitlements are implemented.

## 4 GiB chat attachments

The chat attachment path uses R2 multipart uploads with 8 MiB parts and a configured maximum of 4 GiB per file. It uploads each part to the Worker/R2 binding, completes the multipart object, then posts a chat message referencing that object. Downloads use short-lived single-use tickets and a streamed response instead of buffering the entire file in browser memory.

Start with small files and verify upload/download before trying larger files. This has not been load-tested with a 4 GiB file. Check Cloudflare account limits, R2 storage/operation/egress costs and retention policy before public launch.

## Added routes/pages

- `/social.html`: Stories and Reels URL-based posting/feed; Stories expire after 24 hours; Reels can be liked.
- `/admin.html`: basic counts and report dismissal; protected by `ADMIN_USER_IDS`.
- `/premium.html`: Stripe Checkout entry point; not ready for live payment collection.
- R2 routes: `upload-start`, `upload-part`, `upload-complete`, `upload-abort`, `upload-send`, `download`, `download-file`.
- Stories/Reels routes: `stories-create`, `stories`, `story-delete`, `reel-create`, `reels`, `reel-like`.
- Device routes: `device-register`, `devices`, `device-revoke`.
- E2EE key directory: `e2ee-publish`, `e2ee-key` (public-key lookup only; chat messages are not encrypted).
- Admin routes: `admin`, `admin-report-action`.
- Premium route: `premium-checkout`.

## Security and privacy warnings

- Public-key directory endpoints do not make CHOLLU end-to-end encrypted. Do not advertise E2EE until client-side encryption, identity verification, group key rotation and a security review are complete.
- Group calls are not implemented; the existing calling feature is one-to-one only.
- The device registry is not complete multi-device synchronization.
- Stories/Reels currently accept public HTTPS URLs and do not yet have audience/privacy controls or a full moderation workflow.
- Premium Checkout must remain disabled for real users until verified Stripe webhooks, subscription state, entitlements and cancellation/refund handling exist.
- The existing chat lock is a local-device convenience, not server-enforced protection.
- The existing password/session implementation needs hardening before public launch.
- Review and complete privacy/terms documents, moderation, backup/restore, monitoring and incident response before public launch.

## Google indexing

After deployment on the final public domain, verify the domain in Google Search Console and submit `/sitemap.xml`. Private app content should not be indexed. Search indexing is not guaranteed.

## Local pre-deployment checks

Run `npm test` after `npm install`. This checks JavaScript syntax, Wrangler config structure, and migration syntax/application against a local SQLite database. A passing result is a static check only; it does not prove the app works against your Cloudflare account or that every feature is complete.

## Release acceptance checklist (must be completed before public launch)

- Replace the D1 placeholder ID and verify DB/R2/AI bindings in the target Cloudflare account.
- Apply migrations to a backed-up database, then deploy and inspect Worker logs.
- Test signup, login, logout, one-to-one messages, group membership, permissions, push, and recovery flows with separate test accounts.
- Test file upload/download/abort using small files first; increase size gradually. A 4 GiB configuration is not a tested 4 GiB guarantee.
- Run an independent security review and fix the password/session, CSRF, rate-limit and privacy gaps listed in `FEATURE_STATUS.md`.
- Do not enable real payments, advertise E2EE, or claim group calls / full multi-device sync until those systems are fully implemented and independently tested.
