-- IP-Guard — full backend schema
-- Run this FIRST, in the Supabase SQL editor of your new project.
-- Safe to run once on an empty project.

-- ---------------------------------------------------------------------------
-- 1. Enum types
-- ---------------------------------------------------------------------------
do $$ begin
  create type public.api_service as enum ('virustotal', 'abuseipdb');
exception when duplicate_object then null; end $$;

do $$ begin
  create type public.indicator_type as enum ('ip', 'domain', 'hash');
exception when duplicate_object then null; end $$;

-- ---------------------------------------------------------------------------
-- 2. Shared updated_at helper
-- ---------------------------------------------------------------------------
create or replace function public.update_updated_at_column()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- ---------------------------------------------------------------------------
-- 3. profiles
-- ---------------------------------------------------------------------------
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  display_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

grant select, insert, update, delete on public.profiles to authenticated;
grant all on public.profiles to service_role;

alter table public.profiles enable row level security;

create policy "profiles_own"
  on public.profiles for all
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

create trigger update_profiles_updated_at
  before update on public.profiles
  for each row execute function public.update_updated_at_column();

-- ---------------------------------------------------------------------------
-- 4. api_keys  (VirusTotal / AbuseIPDB keys + IST daily quota tracking)
-- ---------------------------------------------------------------------------
create table public.api_keys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  service public.api_service not null,
  label text not null default 'Key',
  api_key text not null,
  daily_limit integer not null default 500,
  requests_used integer not null default 0,
  -- Quotas roll over at 00:00 IST, so the reset marker is an IST calendar date.
  last_reset_date date not null default ((now() at time zone 'Asia/Kolkata')::date),
  is_active boolean not null default true,
  last_used_at timestamptz,
  created_at timestamptz not null default now()
);

create index api_keys_user_service_idx on public.api_keys (user_id, service);

grant select, insert, update, delete on public.api_keys to authenticated;
grant all on public.api_keys to service_role;

alter table public.api_keys enable row level security;

create policy "api_keys_own"
  on public.api_keys for all
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- 5. scans  (scan history + raw provider payloads)
-- ---------------------------------------------------------------------------
create table public.scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  indicator text not null,
  indicator_type public.indicator_type not null,
  scan_mode text not null default 'single',
  verdict text not null default 'unknown',
  malicious_count integer not null default 0,
  suspicious_count integer not null default 0,
  harmless_count integer not null default 0,
  abuse_score integer,
  reputation integer,
  summary jsonb not null default '{}'::jsonb,
  vt_raw jsonb,
  abuse_raw jsonb,
  error text,
  created_at timestamptz not null default now()
);

create index scans_user_created_idx on public.scans (user_id, created_at desc);
create index scans_user_indicator_idx on public.scans (user_id, indicator);

grant select, insert, update, delete on public.scans to authenticated;
grant all on public.scans to service_role;

alter table public.scans enable row level security;

create policy "scans_own"
  on public.scans for all
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- 6. Auto-create a profile row on sign-up
-- ---------------------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, display_name)
  values (
    new.id,
    new.email,
    coalesce(
      new.raw_user_meta_data->>'display_name',
      new.raw_user_meta_data->>'full_name',
      split_part(new.email, '@', 1)
    )
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();
