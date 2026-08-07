# Data export

CSV snapshots of the current backend, taken at migration time.

| File | Rows | Notes |
| --- | --- | --- |
| `profiles.csv` | user profiles | `id` must match a user in the new project's `auth.users` |
| `api_keys.csv` | VirusTotal / AbuseIPDB keys | contains plaintext keys — handle carefully |
| `scans.csv` | scan history | includes `vt_raw` / `abuse_raw` JSON payloads |

## Import order matters

Rows in all three tables reference `auth.users(id)`. Supabase auth users cannot be
moved with a CSV, so:

1. **Create the users first.** Sign up in the new app with the same email
   addresses. Each sign-up gets a *new* `id`.
2. **Rewrite the ids.** Before importing `scans.csv`, replace the old `user_id`
   values with the new user's id. Same for `api_keys.csv`.
3. `profiles.csv` is normally not needed at all — the `handle_new_user` trigger
   creates profile rows automatically on sign-up. Only import it if you want to
   preserve a custom `display_name`, and then do it as an `update`, not an insert.

## Recommended approach

- **Skip `api_keys.csv`.** Re-add your VirusTotal and AbuseIPDB keys through the
  Settings page in the new app. It's faster than rewriting ids, and it starts the
  daily counters clean instead of carrying over today's usage.
- **Import `scans.csv`** only if you want the history. Easiest path: sign up in the
  new project, then send me the new user id and I'll load the rows for you with
  the ids remapped.

## Manual import

Table Editor → select the table → Insert → Import data from CSV. Make sure the
`user_id` column already holds the new user's id, or the insert fails the foreign
key check.
