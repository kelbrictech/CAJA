-- CÀJA encrypted cloud vault. Jewellery fields never appear in plaintext here.
CREATE TABLE IF NOT EXISTS vaults (
  id TEXT PRIMARY KEY,
  kek_salt TEXT NOT NULL,
  wrapped_key TEXT NOT NULL,
  recovery_salt TEXT NOT NULL,
  recovery_wrap TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 3,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vaults_updated ON vaults(updated_at);
