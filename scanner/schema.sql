-- agentborder scanner storage. One row per meaningful public scan.
-- host is kept for de-duplication and operator audit only. It must never
-- appear in any published research; publish aggregates only.

CREATE TABLE IF NOT EXISTS scans (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  host               TEXT    NOT NULL,
  scanned_at         TEXT    NOT NULL,
  score              INTEGER NOT NULL,
  discoverable       INTEGER NOT NULL DEFAULT 0,
  interactive        INTEGER NOT NULL DEFAULT 0,
  actions            INTEGER NOT NULL DEFAULT 0,
  transaction_paths  INTEGER NOT NULL DEFAULT 0,
  robots_found       INTEGER NOT NULL DEFAULT 0,
  sitemap_found      INTEGER NOT NULL DEFAULT 0,
  security_txt_found INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host);
CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(scanned_at);
