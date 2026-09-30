-- Phase 4F: canonical scanner catalog, controlled result states, and atomic
-- persistence for the authenticated synchronous scan pipeline.

-- Keep all legacy IDs as immutable history. Canonical rows are additive, and the
-- explicit legacy_check_id points from the canonical row to its old catalog key.
alter table public.scan_checks
  add column is_canonical boolean not null default false,
  add column legacy_check_id text,
  add constraint scan_checks_legacy_check_id_fkey
    foreign key (legacy_check_id) references public.scan_checks (check_id) on delete restrict,
  add constraint scan_checks_legacy_map_is_canonical_check
    check (is_canonical or legacy_check_id is null);

create unique index scan_checks_legacy_check_id_unique
  on public.scan_checks (legacy_check_id)
  where legacy_check_id is not null;

insert into public.scan_checks
  (check_id, name, category, description, default_severity, remediation, is_canonical, legacy_check_id)
values
  ('transport.https', 'HTTPS availability', 'transport', 'Checks whether the final response uses HTTPS.', 'high', 'Serve the site over HTTPS and redirect HTTP traffic to HTTPS.', true, 'https'),
  ('transport.http_to_https_redirect', 'HTTP-to-HTTPS redirect', 'transport', 'Checks the observed redirect path from an HTTP request.', 'medium', 'Redirect HTTP requests to the canonical HTTPS origin.', true, 'http_to_https'),
  ('transport.final_scheme', 'Final URL scheme', 'transport', 'Reports the scheme used by the final response URL.', 'informational', 'No remediation is implied by this diagnostic observation.', true, null),
  ('headers.hsts', 'HTTP Strict Transport Security', 'headers', 'Checks for a valid Strict-Transport-Security header.', 'medium', 'Set Strict-Transport-Security after verifying HTTPS is correctly configured.', true, 'hsts'),
  ('headers.csp', 'Content Security Policy', 'headers', 'Checks for a Content-Security-Policy header and selected weak or structural indicators.', 'medium', 'Define a restrictive Content-Security-Policy and test it before enforcement.', true, 'csp'),
  ('headers.x_content_type_options', 'X-Content-Type-Options', 'headers', 'Checks for nosniff content-type protection.', 'low', 'Set X-Content-Type-Options to nosniff.', true, 'x_content_type_options'),
  ('headers.referrer_policy', 'Referrer Policy', 'headers', 'Checks whether observed Referrer-Policy tokens are recognized and suitable.', 'low', 'Set a Referrer-Policy appropriate for the site, such as strict-origin-when-cross-origin.', true, 'referrer_policy'),
  ('headers.permissions_policy', 'Permissions Policy', 'headers', 'Checks Permissions-Policy presence and basic directive syntax.', 'low', 'Disable browser features the site does not need with a Permissions-Policy header.', true, 'permissions_policy'),
  ('headers.frame_protection', 'Frame protection', 'headers', 'Checks CSP frame-ancestors and X-Frame-Options.', 'medium', 'Set CSP frame-ancestors; use X-Frame-Options for older browser compatibility where needed.', true, 'frame_protection'),
  ('exposure.server_headers', 'Server information exposure', 'exposure', 'Observes Server and X-Powered-By response headers without probing.', 'informational', 'Remove or minimize unnecessary server identification headers.', true, 'server_header'),
  ('cookies.security_attributes', 'Cookie security attributes', 'cookies', 'Checks observable cookies for Secure, HttpOnly, and SameSite attributes.', 'medium', 'Set Secure, HttpOnly, and an appropriate SameSite attribute on sensitive cookies.', true, 'secure_cookies'),
  ('content.mixed_http_resources', 'Mixed-content references', 'content', 'Checks safely observed HTML for insecure HTTP resource references.', 'medium', 'Load page resources over HTTPS and update insecure resource references.', true, 'mixed_content'),
  ('technology.passive_indicators', 'Passive technology indicators', 'technology', 'Identifies an allowlist of passive response-header and HTML markers.', 'informational', 'No remediation is implied by passive technology indicators.', true, null)
on conflict (check_id) do update
  set is_canonical = excluded.is_canonical,
      legacy_check_id = excluded.legacy_check_id;

-- A scan has one controlled lifecycle. Translate the previous vocabulary before
-- tightening the constraint so the migration also handles non-empty databases.
alter table public.scans drop constraint scans_status_check;
update public.scans
set status = case status
  when 'created' then 'pending'
  when 'validating' then 'pending'
  when 'scanning' then 'running'
  else status
end;
alter table public.scans alter column status set default 'pending';
alter table public.scans
  add constraint scans_status_check
    check (status in ('pending', 'running', 'completed', 'failed'));

alter table public.scans
  add column scoring_version text,
  add column score_confidence text,
  add column score_available boolean not null default false,
  add column score_details jsonb not null default '{}'::jsonb,
  add column error_code text;

update public.scans
set score_available = score is not null;

alter table public.scans
  add constraint scans_scoring_version_check
    check (scoring_version is null or length(scoring_version) between 1 and 32),
  add constraint scans_score_confidence_check
    check (score_confidence is null or score_confidence in ('complete', 'partial', 'limited')),
  add constraint scans_score_availability_check
    check ((score_available and score is not null) or (not score_available and score is null)),
  add constraint scans_score_details_object_check
    check (jsonb_typeof(score_details) = 'object'),
  add constraint scans_error_code_check
    check (error_code is null or error_code in (
      'invalid_target', 'blocked_target', 'network_failure', 'timeout',
      'scanner_error', 'persistence_failure'
    ));

-- Keep the established columns: findings.description is the scanner summary and
-- findings.recommendation is remediation. Add only the narrative fields absent
-- from the original catalog and scrub old NULL evidence to a structured object.
alter table public.findings drop constraint findings_status_check;
alter table public.findings drop constraint findings_severity_check;
update public.findings set status = 'pass' where status = 'passed';
update public.findings set status = 'fail' where status = 'failed';
update public.findings set severity = 'informational' where severity = 'passed';
update public.findings set evidence = '{}'::jsonb where evidence is null;
alter table public.findings
  alter column evidence set default '{}'::jsonb,
  alter column evidence set not null,
  add column why_it_matters text not null default 'Not recorded for this legacy finding.',
  add column affected_url text not null default '',
  add column metadata jsonb not null default '{}'::jsonb,
  add constraint findings_status_check
    check (status in ('pass', 'fail', 'warn', 'not_applicable', 'error')),
  add constraint findings_severity_check
    check (severity in ('critical', 'high', 'medium', 'low', 'informational')),
  add constraint findings_metadata_object_check
    check (jsonb_typeof(metadata) = 'object');

-- Preserve the existing numeric confidence for schema compatibility and retain
-- the scanner's exact controlled confidence label separately.
alter table public.technologies
  add column confidence_label text,
  add column evidence jsonb not null default '[]'::jsonb,
  add column metadata jsonb not null default '{}'::jsonb,
  add constraint technologies_confidence_label_check
    check (confidence_label is null or confidence_label in ('low', 'medium', 'high')),
  add constraint technologies_evidence_array_check
    check (jsonb_typeof(evidence) = 'array'),
  add constraint technologies_metadata_object_check
    check (jsonb_typeof(metadata) = 'object');

create table public.scan_check_results (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  check_id text not null references public.scan_checks (check_id) on delete restrict,
  status text not null check (
    status in ('pass', 'fail', 'warn', 'not_applicable', 'error')
  ),
  severity text check (
    severity is null or severity in ('critical', 'high', 'medium', 'low', 'informational')
  ),
  scoring_relevant boolean not null,
  scoring_version text not null check (length(scoring_version) between 1 and 32),
  check_version text not null check (length(check_version) between 1 and 32),
  reason text not null,
  evidence jsonb not null default '{}'::jsonb check (jsonb_typeof(evidence) = 'object'),
  score_explanation jsonb not null check (jsonb_typeof(score_explanation) = 'object'),
  created_at timestamptz not null default now(),
  unique (scan_id, check_id)
);

alter table public.scan_check_results enable row level security;
revoke all on table public.scan_check_results from public, anon, authenticated, service_role;
grant select on table public.scan_check_results to authenticated;
grant select, insert, update, delete on table public.scan_check_results to service_role;

create policy "scan_check_results_select_for_owned_scans"
  on public.scan_check_results for select to authenticated
  using (
    exists (
      select 1 from public.scans
      where public.scans.id = scan_check_results.scan_id
        and public.scans.user_id = (select auth.uid())
    )
  );

-- Keep privileged persistence in one Postgres transaction. The RPC is callable
-- only by service_role; it also verifies that every canonical finding/result is
-- present before atomically completing the scan.
create or replace function public.persist_completed_scan(
  p_scan_id uuid,
  p_user_id uuid,
  p_normalized_url text,
  p_score smallint,
  p_score_available boolean,
  p_scoring_version text,
  p_score_confidence text,
  p_score_details jsonb,
  p_completed_at timestamptz,
  p_duration_ms integer,
  p_findings jsonb,
  p_technologies jsonb,
  p_check_results jsonb
)
returns void
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  canonical_count integer;
  finding_count integer;
  check_result_count integer;
begin
  if jsonb_typeof(p_findings) is distinct from 'array'
     or jsonb_typeof(p_technologies) is distinct from 'array'
     or jsonb_typeof(p_check_results) is distinct from 'array'
     or jsonb_typeof(p_score_details) is distinct from 'object' then
    raise exception using errcode = '22023', message = 'Invalid scan result payload.';
  end if;

  if p_score_available is distinct from (p_score is not null)
     or p_score_confidence is null
     or p_score_confidence not in ('complete', 'partial', 'limited')
     or p_scoring_version is null
     or length(p_scoring_version) not between 1 and 32
     or p_normalized_url is null
     or p_duration_ms is null
     or p_duration_ms < 0 then
    raise exception using errcode = '22023', message = 'Invalid scan score metadata.';
  end if;

  select count(*) into canonical_count
  from public.scan_checks
  where is_canonical;

  if canonical_count <> 13 then
    raise exception using errcode = '22023', message = 'Canonical check catalog must contain exactly 13 rows.';
  end if;

  select count(*) into finding_count
  from jsonb_to_recordset(p_findings) as item(check_id text);

  select count(*) into check_result_count
  from jsonb_to_recordset(p_check_results) as item(check_id text);

  if finding_count <> canonical_count or check_result_count <> canonical_count
     or exists (
       select check_id from public.scan_checks where is_canonical
       except
       select item.check_id from jsonb_to_recordset(p_findings) as item(check_id text)
     )
     or exists (
       select check_id from public.scan_checks where is_canonical
       except
       select item.check_id from jsonb_to_recordset(p_check_results) as item(check_id text)
     )
     or exists (
       select item.check_id from jsonb_to_recordset(p_findings) as item(check_id text)
       left join public.scan_checks catalog on catalog.check_id = item.check_id
       where catalog.is_canonical is distinct from true
     )
     or exists (
       select item.check_id from jsonb_to_recordset(p_check_results) as item(check_id text)
       left join public.scan_checks catalog on catalog.check_id = item.check_id
       where catalog.is_canonical is distinct from true
     ) then
    raise exception using errcode = '22023', message = 'Scan results do not match the canonical check catalog.';
  end if;

  update public.scans
  set status = 'completed',
      normalized_url = p_normalized_url,
      score = p_score,
      score_available = p_score_available,
      scoring_version = p_scoring_version,
      score_confidence = p_score_confidence,
      score_details = p_score_details,
      completed_at = p_completed_at,
      duration_ms = p_duration_ms,
      error_code = null,
      error_message = null
  where id = p_scan_id and user_id = p_user_id and status = 'running';

  if not found then
    raise exception using errcode = 'P0001', message = 'Scan ownership or lifecycle check failed.';
  end if;

  insert into public.findings (
    scan_id, check_id, title, severity, status, description,
    why_it_matters, evidence, recommendation, affected_url, metadata
  )
  select p_scan_id, item.check_id, item.title, item.severity, item.status,
         item.summary, item.why_it_matters, item.evidence, item.remediation,
         item.affected_url, item.metadata
  from jsonb_to_recordset(p_findings) as item(
    check_id text, title text, severity text, status text, summary text,
    why_it_matters text, evidence jsonb, remediation text,
    affected_url text, metadata jsonb
  );

  insert into public.technologies (
    scan_id, name, category, confidence, confidence_label, evidence, metadata
  )
  select p_scan_id, item.name, item.category, item.confidence,
         item.confidence_label, item.evidence, item.metadata
  from jsonb_to_recordset(p_technologies) as item(
    name text, category text, confidence numeric, confidence_label text,
    evidence jsonb, metadata jsonb
  );

  insert into public.scan_check_results (
    scan_id, check_id, status, severity, scoring_relevant,
    scoring_version, check_version, reason, evidence, score_explanation
  )
  select p_scan_id, item.check_id, item.status, item.severity,
         item.scoring_relevant, item.scoring_version, item.check_version,
         item.reason, item.evidence, item.score_explanation
  from jsonb_to_recordset(p_check_results) as item(
    check_id text, status text, severity text, scoring_relevant boolean,
    scoring_version text, check_version text, reason text, evidence jsonb,
    score_explanation jsonb
  );
end;
$function$;

revoke all on function public.persist_completed_scan(
  uuid, uuid, text, smallint, boolean, text, text, jsonb, timestamptz,
  integer, jsonb, jsonb, jsonb
) from public, anon, authenticated;
grant execute on function public.persist_completed_scan(
  uuid, uuid, text, smallint, boolean, text, text, jsonb, timestamptz,
  integer, jsonb, jsonb, jsonb
) to service_role;
