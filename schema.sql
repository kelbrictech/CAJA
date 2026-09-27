-- CÀJA zero-knowledge cloud schema
CREATE TABLE IF NOT EXISTS vaults (
  id TEXT PRIMARY KEY,
  auth_hash TEXT NOT NULL,
  kek_salt TEXT NOT NULL,
  wrapped_key TEXT NOT NULL,
  recovery_salt TEXT NOT NULL,
  recovery_wrap TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vaults_updated ON vaults(updated_at);
