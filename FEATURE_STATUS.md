# CHOLLU — Feature status (development build)

This package extends the uploaded CHOLLU project. It is **not production-ready** and has not been deployed to the user's Cloudflare account.

## Implemented in this package (requires Cloudflare configuration)
- Existing signup/login, private chats, groups, replies, reactions, edits/deletes, disappearing messages, profile, push notification support, AI chat and basic one-to-one WebRTC call signaling.
- **Chat file sharing through Cloudflare R2 multipart uploads**, configured for up to 4 GiB per file using 8 MiB parts. Includes ownership checks, group membership checks, upload completion/abort, short-lived download tickets and streaming download responses. Not load-tested at 4 GiB; test with small files first and check Cloudflare limits/costs.
- Stories API and social page. Stories expire after 24 hours. Current posting method accepts a public HTTPS media URL; in-app R2 media upload, visibility controls and moderation are not complete.
- Reels API and social page with likes. Current posting method accepts a public HTTPS video URL; upload/transcoding, comments, recommendation feed and moderation are not complete.
- Admin dashboard for basic user/message counts and report dismissal. Requires `ADMIN_USER_IDS`. It is not a complete admin/moderation suite.
- Premium Checkout session endpoint and basic checkout page. Requires Stripe configuration. **Do not accept payments yet**: webhook signature verification, persisted subscription status, entitlements, cancellation/refunds and tax handling are not implemented.
- Device registry/list/remove UI. This is not full multi-device message/state synchronization, secure key transfer or complete remote session revocation.
- E2EE public-key directory endpoints only. **Messages and files are not end-to-end encrypted.** No key verification, key rotation, client encryption/decryption or audited protocol is implemented.
- SEO basics, robots.txt, sitemap.xml, PWA manifest and privacy/terms starter pages.

## Not yet implemented / requires further engineering
- Real end-to-end encryption for direct and group chats and attachments, using a reviewed protocol and identity verification.
- Group calls. Existing call signaling is one-to-one; group calls require an SFU/media server, group signaling, TURN configuration and reconnect/participant handling.
- Complete Stories/Reels upload and playback experience, audience controls, expiry cleanup, reports and moderation.
- Premium subscription lifecycle and actual feature entitlement enforcement.
- Full multi-device sync, encrypted key transfer, synchronized read state and revocation of all sessions.
- Production security hardening: Argon2id/PBKDF2 password hashing, HttpOnly secure cookies, CSRF protections, robust rate limiting, account verification, audit logging, backup/restore, monitoring and independent security review.

## Important deployment notes
- Create a D1 database and an R2 bucket named `chollu-files` (or change the bucket name in `wrangler.jsonc`).
- For a new empty D1 database, apply migrations 0001 and 0002. For an existing database already using migration 0001, apply only migration 0002 after a backup.
- Set a real D1 database ID in `wrangler.jsonc`.
- Generate a **new** VAPID key pair. A private key was included in an earlier user upload and must be treated as exposed. Never commit secrets to GitHub.
- Large files consume R2 storage and operation resources. Check current Cloudflare plan limits, pricing and retention requirements.
- The current password/session implementation is not suitable for a public production launch without security work.

## Revision 1.2.0 (added)
- Passwords: PBKDF2-SHA256 (100k iterations). Old SHA-256 hashes are upgraded automatically on next successful login.
- Rate limits: signup (10/hour/IP) and forgot-password (5/hour/IP), in addition to the existing login lockout.
- Sessions: `logout` and `logout-all` (other devices) endpoints; the app calls logout and the Devices panel has a "log out other devices" button.
- Premium: Stripe webhook with signature + timestamp verification, idempotent events, `subscriptions` table, `premium-status`, `premium-portal`, duplicate-subscription guard. **No feature is gated by Premium yet** (product decision); use `premium-status` server-side before gating anything. Test in Stripe test mode first.
- Stories: audience control (everyone / only people you have chatted with); blocked users are hidden from Stories and Reels.
- Files: deleting a file message deletes the R2 object; upload-send respects blocks.
- Hourly cron cleanup (`triggers.crons`): expired stories, messages, sessions, download tickets, signals, reset codes, old rate-limit rows, stale multipart uploads.
- `npm test` now also runs `scripts/api-test.mjs` (26 API checks against an in-memory SQLite D1 stand-in).

Still NOT done: real E2EE, group calls, Stories/Reels media upload to R2 and moderation queue, full multi-device sync, independent security review. See FEATURE_ROADMAP.md.
New settings: secret `STRIPE_WEBHOOK_SECRET`; Stripe webhook endpoint `https://YOUR-DOMAIN/api/stripe-webhook` (events: checkout.session.completed, customer.subscription.created/updated/deleted, invoice.payment_failed). Apply `migrations/0003_billing_audience.sql` (existing DB: only 0003).

## Revision 1.3.0 (added)
- Stories/Reels media upload to private R2 (`media-upload`): JPEG/PNG/WebP/GIF up to 10 MB, MP4/WebM/MOV up to 90 MB, 500 MB per-user quota. Served via unguessable capability URLs (`/api/media?id=...`) with Range support, `nosniff` and a locked-down CSP. URL posting still works.
- Media is deleted from R2 when a story/reel is deleted, expires, or is removed by an admin.
- Content moderation: users can report a story/reel (20/day); admins see a "Stories/Reels reports" queue and can Remove (deletes post + media + all its reports) or Dismiss; actions are written to `admin_audit`. Owners can delete their own story/reel.
- Apply `migrations/0004_media_moderation.sql` (existing DB: only 0004 after 0003).
- Known limits: no video transcoding/thumbnails, no file-content (magic byte) scanning, no automated abuse detection, no comments, media URLs are capability links (anyone holding the link can view until deleted).

## Revision 1.4.0 (added)
- Reel comments (create/list/delete; authors and the reel owner can delete; block-aware; 30/hour limit) shown in the Reels list.
- Story view counts (shown to the story owner only; only counts people allowed to see the story).
- Apply `migrations/0005_comments_views.sql` (existing DB: only 0005 after 0004).
- Not added: comment reporting/moderation, viewer list, notifications for comments.
