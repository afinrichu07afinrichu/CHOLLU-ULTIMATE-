-- CHOLLU secure messaging, device sync, and group-call groundwork.
-- Apply only after reviewing against the current production schema.
-- This migration deliberately stores public keys and opaque ciphertext only.

PRAGMA foreign_keys=ON;

-- Multiple independently revocable devices per account. Private keys MUST remain
-- on the user's devices and must never be uploaded to this table.
CREATE TABLE IF NOT EXISTS secure_devices (
  uid INTEGER NOT NULL,
  device_id TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  identity_public_key TEXT NOT NULL,
  signed_prekey_public TEXT,
  signed_prekey_signature TEXT,
  last_seen INTEGER NOT NULL,
  revoked_at INTEGER,
  PRIMARY KEY (uid, device_id)
);
CREATE INDEX IF NOT EXISTS secure_devices_active_idx
  ON secure_devices(uid, revoked_at, last_seen);

-- One-time public prekeys support asynchronous device-to-device key setup.
-- The server may publish/consume these public values, never private material.
CREATE TABLE IF NOT EXISTS secure_one_time_prekeys (
  uid INTEGER NOT NULL,
  device_id TEXT NOT NULL,
  prekey_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  created INTEGER NOT NULL,
  consumed_at INTEGER,
  PRIMARY KEY (uid, device_id, prekey_id)
);
CREATE INDEX IF NOT EXISTS secure_prekeys_available_idx
  ON secure_one_time_prekeys(uid, device_id, consumed_at);

-- Opaque client-encrypted state changes for multi-device synchronization.
-- The server can order/expire events but must not decrypt payloads.
CREATE TABLE IF NOT EXISTS device_sync_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid INTEGER NOT NULL,
  source_device_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS device_sync_events_cursor_idx
  ON device_sync_events(uid, id);

-- Call room metadata and signaling are not media encryption. A production
-- group-call implementation must use an authenticated SFU and audited E2EE
-- media insertable streams/SFrame before it can claim private group calls.
CREATE TABLE IF NOT EXISTS call_rooms (
  id TEXT PRIMARY KEY,
  owner_uid INTEGER NOT NULL,
  conversation_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'ringing',
  created INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS call_room_members (
  room_id TEXT NOT NULL,
  uid INTEGER NOT NULL,
  device_id TEXT NOT NULL,
  joined_at INTEGER,
  left_at INTEGER,
  PRIMARY KEY (room_id, uid, device_id)
);
CREATE INDEX IF NOT EXISTS call_room_members_uid_idx
  ON call_room_members(uid, room_id);
CREATE TABLE IF NOT EXISTS call_room_signals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id TEXT NOT NULL,
  from_uid INTEGER NOT NULL,
  to_uid INTEGER NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS call_room_signals_poll_idx
  ON call_room_signals(to_uid, id, created);
