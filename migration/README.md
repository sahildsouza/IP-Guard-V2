# Migrating IP-Guard to your own Supabase project

This folder recreates the IP-Guard backend on a Supabase project you own
(org: **sahil's projects**). Nothing here touches or breaks the current project —
it keeps working as a fallback until the new one is verified.

## Why a new Lovable project is needed

This project runs on Lovable Cloud. Cloud is Supabase underneath, but it cannot be
detached or repointed at a different Supabase project. So the app moves to a fresh
Lovable project that has your own Supabase account connected instead of Cloud.

## Runbook

### Step 1 — Create the Supabase project

In the Supabase dashboard, create a new project inside the **sahil's projects** org.
Pick a region close to you and save the database password somewhere safe.

### Step 2 — Create the schema

Open SQL Editor → New query → paste all of [`01_schema.sql`](./01_schema.sql) → Run.

This creates: the `api_service` / `indicator_type` enums, the `profiles`,
`api_keys` and `scans` tables with grants, RLS and owner-only policies, the
`updated_at` trigger, and the `handle_new_user` trigger that creates a profile row
on sign-up.

### Step 3 — Create the storage bucket

Storage → New bucket:

- Name: `bulk-uploads`
- Public: **off**

### Step 4 — Add the storage rules

SQL Editor → paste [`02_storage.sql`](./02_storage.sql) → Run.

### Step 5 — Configure auth

Follow [`03_auth_setup.md`](./03_auth_setup.md): email/password, Google provider,
anonymous sign-ins off, Site URL and redirect URLs.

### Step 6 — Create the new Lovable project and connect Supabase

1. Create a new Lovable project. Do **not** enable Lovable Cloud on it.
2. Connectors → Supabase → connect your account and select the project from
   Step 1.
3. This injects `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`,
   `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` and `SUPABASE_SERVICE_ROLE_KEY` —
   the same names the app already reads, so no config edits are needed.

### Step 7 — Bring the app code across

In the new project, ask me to copy IP-Guard's source over from this project. Then
ask me to apply the Google sign-in swap described in `03_auth_setup.md` and
regenerate `src/integrations/supabase/types.ts` from the new schema.

### Step 8 — Import existing data (optional)

See [`04_data_export/README.md`](./04_data_export/README.md).

### Step 9 — Verify

- Sign up with email → a row appears in `profiles`.
- Sign in with Google → returns to the app signed in.
- Settings → add a VirusTotal key and an AbuseIPDB key.
- Checker → single IP scan returns a verdict; `scans` gains a row and the key's
  `requests_used` increments.
- Checker → bulk paste of 3 indicators streams results with the progress queue.
- Checker → upload a small `.xlsx`; confirm it lands in `bulk-uploads` under your
  user id.
- Dashboard → stats, trend chart and quota bars populate.
- Export CSV and Excel from a bulk result set.

## Notes

- API keys are stored in plaintext in `api_keys`, same as today. RLS keeps them
  owner-only, but consider moving to Supabase Vault later if you want them
  encrypted at rest.
- The daily quota reset is lazy: `last_reset_date` is compared against the current
  IST date on each scan, so no cron job is required.
