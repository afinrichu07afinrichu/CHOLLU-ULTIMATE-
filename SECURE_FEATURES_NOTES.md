# Secure-feature implementation notes

This branch adds database groundwork only. It does **not** activate E2EE, group calls, or multi-device synchronization, and must not be advertised as providing them. The current application stores chat message bodies in server-readable form; its existing public-key lookup endpoint is not encryption.

## Security requirements before enabling E2EE

- Adopt and independently review a maintained protocol/library (for example, a Signal Protocol implementation); do not invent a production protocol from the schema.
- Perform encryption/decryption on clients. Keep identity private keys, signed-prekey private keys, one-time prekey private keys, and message keys on the device; do not send them to the Worker or D1.
- Add authenticated device enrollment, identity-key verification/safety numbers, prekey rotation and consumption, replay protection, group membership/key rotation, encrypted attachment keys, and recovery behavior.
- Ensure server APIs accept and return opaque ciphertext and never pass plaintext to AI, push payloads, logs, moderation, or analytics. Existing server-side chat search, AI replies, and plaintext storage must be redesigned or explicitly disabled for encrypted conversations.
- Test tampering, malformed envelopes, key changes, revocation, stale devices, and backups. Obtain an independent cryptographic security review before making an E2EE claim.

## Multi-device synchronization requirements

- Authenticate each device separately and bind every event to an active device key.
- Encrypt sync event payloads on the sender and decrypt only on authorized devices.
- Add bounded cursor-based fetch, idempotency, retention/cleanup, replay handling, conflict resolution, and device revocation that invalidates tokens and future key delivery.
- Do not replicate secrets or plaintext messages through `device_sync_events`.

## Group calls requirements

- Choose and provision an SFU/media provider; this migration alone provides no media transport.
- Implement authorized room creation/join/leave, short-lived provider credentials, signaling validation, reconnect and participant controls, abuse limits, and cleanup.
- WebRTC transport encryption alone is not end-to-end encryption when an SFU can access media. Use a reviewed SFrame/insertable-streams design if E2EE group media is required.
- Validate browser/mobile compatibility, TURN/SFU configuration, call limits, and operational costs.

## Applying this migration

Back up D1, inspect the existing migration state, then apply migration 0006 after 0005 using the project's Wrangler migration workflow. Do not apply it to a production database until the schema and retention policy have been reviewed. The new tables are intentionally not wired to API routes or UI yet; enabling them requires the implementation and security work above.
