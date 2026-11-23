CREATE TABLE IF NOT EXISTS subscriptions(uid INTEGER PRIMARY KEY,customer TEXT,sub_id TEXT,status TEXT NOT NULL,period_end INTEGER DEFAULT 0,updated INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS subs_customer_idx ON subscriptions(customer);
CREATE TABLE IF NOT EXISTS stripe_events(id TEXT PRIMARY KEY,created INTEGER NOT NULL);
ALTER TABLE stories ADD COLUMN audience TEXT NOT NULL DEFAULT 'everyone';
