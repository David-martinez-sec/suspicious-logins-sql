BEGIN TRANSACTION;
DROP TABLE IF EXISTS logins;
CREATE TABLE logins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  username TEXT NOT NULL,
  timestamp TEXT NOT NULL, -- ISO 8601, e.g., 2025-08-12T09:10:00
  ip_address TEXT NOT NULL,
  status TEXT CHECK(status IN ('success','failure')) NOT NULL
);
CREATE INDEX idx_logins_username_time ON logins(username, timestamp);
CREATE INDEX idx_logins_status ON logins(status);
COMMIT;
