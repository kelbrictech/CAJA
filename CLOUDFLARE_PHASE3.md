# CÀJA Phase 3 Cloud Activation

The repository is wired for ciphertext-only D1 sync and client-encrypted R2 assets. The resources still have to exist in the Cloudflare account.

Run from the repository with an authenticated Wrangler session:

```powershell
npx wrangler d1 create caja-vault
npx wrangler r2 bucket create caja-vault-assets
```

Copy the returned D1 database ID into the commented `d1_databases` block in `wrangler.jsonc`, then uncomment both D1 and R2 binding blocks.

Apply the encrypted schema and deploy:

```powershell
npx wrangler d1 execute caja-vault --remote --file=./schema.sql
npx wrangler deploy
```

Verify:

```powershell
Invoke-RestMethod https://caja.arjayb-fb.workers.dev/api/sync/config
Invoke-RestMethod https://caja.arjayb-fb.workers.dev/api/status
```

Expected after activation: `d1: true` and `r2: true`.

Security boundary: D1 receives encrypted vault envelopes and wrapped keys, R2 receives AES-GCM ciphertext only. The raw Vault Key and plaintext jewellery/files remain client-side.
