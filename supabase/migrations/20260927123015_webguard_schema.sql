-- WebGuard Phase 2: Auth profiles, scans, results, and check catalog.
-- Client access is explicitly granted below; row-level policies enforce ownership.

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  display_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Keep profile provisioning atomic with Auth signup. User metadata is not used
-- for authorization; display_name is an optional, user-editable profile field.
create or replace function private.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $function$
begin
  insert into public.profiles (id, email, display_name)
  values (new.id, new.email, nullif(new.raw_user_meta_data ->> 'display_name', ''));
  return new;
end;
$function$;

revoke all on function private.handle_new_user() from public, anon, authenticated;
grant usage on schema private to supabase_auth_admin;
grant execute on function private.handle_new_user() to supabase_auth_admin;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function private.handle_new_user();

create table public.scan_checks (
  check_id text primary key,
  name text not null,
  category text not null,
  description text not null,
  default_severity text not null check (
    default_severity in ('critical', 'high', 'medium', 'low', 'informational')
  ),
  remediation text not null,
  created_at timestamptz not null default now()
);

create table public.scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  target_url text not null check (length(target_url) between 1 and 2048),
  normalized_url text check (
    normalized_url is null or length(normalized_url) between 1 and 2048
  ),
  status text not null default 'created' check (
    status in ('created', 'validating', 'scanning', 'completed', 'failed')
  ),
  score smallint check (score is null or score between 0 and 100),
  started_at timestamptz,
  completed_at timestamptz,
  duration_ms integer check (duration_ms is null or duration_ms >= 0),
  error_message text,
  created_at timestamptz not null default now(),
  check (completed_at is null or started_at is null or completed_at >= started_at)
);

create table public.findings (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  check_id text not null references public.scan_checks (check_id) on delete restrict,
  title text not null,
  severity text not null check (
    severity in ('critical', 'high', 'medium', 'low', 'informational', 'passed')
  ),
  status text not null check (
    status in ('passed', 'failed', 'not_applicable', 'error')
  ),
  description text not null,
  evidence jsonb,
  recommendation text not null,
  created_at timestamptz not null default now(),
  unique (scan_id, check_id)
);

create table public.technologies (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  name text not null,
  category text not null,
  confidence numeric(4, 3) check (
    confidence is null or confidence between 0 and 1
  ),
  created_at timestamptz not null default now(),
  unique (scan_id, name, category)
);

-- Severity labels are descriptive only; score weights/formula are intentionally
-- unspecified until the documented scoring-design task is completed.
insert into public.scan_checks
  (check_id, name, category, description, default_severity, remediation)
values
  ('https', 'HTTPS usage', 'transport', 'Checks whether the target uses HTTPS.', 'high', 'Serve the site over HTTPS and redirect HTTP traffic to HTTPS.'),
  ('http_to_https', 'HTTP to HTTPS redirect', 'transport', 'Checks whether HTTP requests redirect to HTTPS.', 'medium', 'Redirect HTTP requests to the canonical HTTPS origin.'),
  ('hsts', 'HTTP Strict Transport Security', 'headers', 'Checks for a valid Strict-Transport-Security header.', 'medium', 'Set Strict-Transport-Security after verifying HTTPS is correctly configured.'),
  ('csp', 'Content Security Policy', 'headers', 'Checks for a Content-Security-Policy header.', 'medium', 'Define a restrictive Content-Security-Policy and test it before enforcement.'),
  ('x_content_type_options', 'X-Content-Type-Options', 'headers', 'Checks for nosniff content-type protection.', 'low', 'Set X-Content-Type-Options to nosniff.'),
  ('referrer_policy', 'Referrer Policy', 'headers', 'Checks for a Referrer-Policy header.', 'low', 'Set a Referrer-Policy appropriate for the site, such as strict-origin-when-cross-origin.'),
  ('permissions_policy', 'Permissions Policy', 'headers', 'Checks for a Permissions-Policy header.', 'low', 'Disable browser features the site does not need with a Permissions-Policy header.'),
  ('frame_protection', 'Frame protection', 'headers', 'Checks CSP frame-ancestors and X-Frame-Options.', 'medium', 'Set CSP frame-ancestors; use X-Frame-Options for older browser compatibility where needed.'),
  ('secure_cookies', 'Cookie security attributes', 'cookies', 'Checks observable cookies for Secure, HttpOnly, and SameSite attributes.', 'medium', 'Set Secure, HttpOnly, and an appropriate SameSite attribute on sensitive cookies.'),
  ('server_header', 'Server information exposure', 'headers', 'Checks whether response headers disclose server implementation details.', 'informational', 'Remove or minimize unnecessary server identification headers.'),
  ('mixed_content', 'Mixed content indicators', 'content', 'Checks safely observable content for insecure mixed-content references.', 'medium', 'Load page resources over HTTPS and update insecure resource references.');

create index scans_user_created_at_idx on public.scans (user_id, created_at desc);
create index findings_scan_id_idx on public.findings (scan_id);
create index findings_check_id_idx on public.findings (check_id);

alter table public.profiles enable row level security;
alter table public.scan_checks enable row level security;
alter table public.scans enable row level security;
alter table public.findings enable row level security;
alter table public.technologies enable row level security;

-- Explicit grants are required independently of RLS. In particular, signed-out
-- clients get no table access even where policies also deny all rows.
revoke all on table public.profiles, public.scan_checks, public.scans,
  public.findings, public.technologies from anon, authenticated, service_role;
grant usage on schema public to authenticated, service_role;

grant select, insert, update on table public.profiles to authenticated;
grant select on table public.scan_checks to authenticated;
grant select, delete on table public.scans to authenticated;
grant select on table public.findings, public.technologies to authenticated;

-- Privileged backend persistence must validate the caller JWT and derive user_id
-- from its verified `sub` claim; the client never supplies an authoritative ID.
grant select, insert, update, delete on table public.profiles, public.scans,
  public.findings, public.technologies, public.scan_checks to service_role;

create policy "profiles_select_own"
  on public.profiles for select to authenticated
  using ((select auth.uid()) = id);
create policy "profiles_insert_own"
  on public.profiles for insert to authenticated
  with check ((select auth.uid()) = id);
create policy "profiles_update_own"
  on public.profiles for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

create policy "scan_checks_read_authenticated"
  on public.scan_checks for select to authenticated
  using ((select auth.uid()) is not null);

create policy "scans_select_own"
  on public.scans for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "scans_delete_own"
  on public.scans for delete to authenticated
  using ((select auth.uid()) = user_id);

create policy "findings_select_for_owned_scans"
  on public.findings for select to authenticated
  using (
    exists (
      select 1 from public.scans
      where public.scans.id = findings.scan_id
        and public.scans.user_id = (select auth.uid())
    )
  );

create policy "technologies_select_for_owned_scans"
  on public.technologies for select to authenticated
  using (
    exists (
      select 1 from public.scans
      where public.scans.id = technologies.scan_id
        and public.scans.user_id = (select auth.uid())
    )
  );
