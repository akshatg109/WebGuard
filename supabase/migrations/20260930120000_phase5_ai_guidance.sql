-- Phase 5: persist opt-in AI guidance without changing deterministic scan data.

create table public.scan_ai_summaries (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null unique references public.scans (id) on delete cascade,
  summary jsonb not null check (jsonb_typeof(summary) = 'object'),
  evidence_hash text not null check (evidence_hash ~ '^[0-9a-f]{64}$'),
  generated_at timestamptz not null default now(),
  provider text not null check (length(provider) between 1 and 80),
  model text not null check (length(model) between 1 and 160),
  prompt_version text not null check (length(prompt_version) between 1 and 32)
);

-- PostgreSQL requires an exact unique key for the composite FK below. The
-- existing findings primary key on id does not satisfy (scan_id, id).
create unique index findings_scan_id_id_idx on public.findings (scan_id, id);

create table public.finding_ai_explanations (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  finding_id uuid not null,
  explanation jsonb not null check (jsonb_typeof(explanation) = 'object'),
  evidence_hash text not null check (evidence_hash ~ '^[0-9a-f]{64}$'),
  generated_at timestamptz not null default now(),
  provider text not null check (length(provider) between 1 and 80),
  model text not null check (length(model) between 1 and 160),
  prompt_version text not null check (length(prompt_version) between 1 and 32),
  unique (finding_id),
  foreign key (scan_id, finding_id)
    references public.findings (scan_id, id) on delete cascade
);

create index finding_ai_explanations_scan_id_idx
  on public.finding_ai_explanations (scan_id);

alter table public.scan_ai_summaries enable row level security;
alter table public.finding_ai_explanations enable row level security;

revoke all on table public.scan_ai_summaries, public.finding_ai_explanations
  from public, anon, authenticated, service_role;
grant select on table public.scan_ai_summaries, public.finding_ai_explanations
  to authenticated;
grant select, insert, update, delete
  on table public.scan_ai_summaries, public.finding_ai_explanations
  to service_role;

create policy "scan_ai_summaries_read_for_owned_scans"
  on public.scan_ai_summaries for select to authenticated
  using (
    exists (
      select 1 from public.scans
      where public.scans.id = scan_ai_summaries.scan_id
        and public.scans.user_id = (select auth.uid())
    )
  );

create policy "finding_ai_explanations_read_for_owned_scans"
  on public.finding_ai_explanations for select to authenticated
  using (
    exists (
      select 1
      from public.findings
      join public.scans on public.scans.id = public.findings.scan_id
      where public.findings.id = finding_ai_explanations.finding_id
        and public.findings.scan_id = finding_ai_explanations.scan_id
        and public.scans.user_id = (select auth.uid())
    )
  );
