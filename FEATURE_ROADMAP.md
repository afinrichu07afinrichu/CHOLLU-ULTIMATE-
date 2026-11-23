# Remaining work before public launch

1. E2EE: choose a reviewed protocol (e.g. Signal Protocol implementation), add device identity keys, safety-number verification, encrypted message/attachment payloads, group sender keys, key rotation, recovery and security audit. Do not roll custom cryptography.
2. Group calls: select a supported SFU (Cloudflare Calls or another provider), implement room authorization, group signaling, participant controls, TURN/SFU secrets, reconnect handling and load tests.
3. Stories/Reels: (done: R2 upload, audience, expiry cleanup, reports, admin moderation, quotas) remaining: transcoding/thumbnails, view tracking, comments, automated scanning.
4. Premium: implement Stripe webhook signature verification, subscription table, idempotent event handling, entitlement checks, cancellation/refunds, customer portal and test-mode verification before live mode.
5. Multi-device: encrypted device pairing, session/token revocation, synchronized message state, per-device push subscriptions, E2EE key distribution and conflict handling.
6. Production hardening: replace password hashing/session storage, add secure cookies and CSRF, rate limits, abuse controls, backups, monitoring, privacy/terms review and independent penetration testing.
