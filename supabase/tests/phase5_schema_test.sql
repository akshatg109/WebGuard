begin;
select plan(8);

select ok(
  exists (
    select 1
    from pg_constraint
    where conrelid = 'public.findings'::regclass
      and conname = 'findings_pkey'
      and contype = 'p'
      and pg_get_constraintdef(oid) = 'PRIMARY KEY (id)'
  ),
  'the existing findings primary key remains on id'
);
select ok(
  exists (
    select 1
    from pg_indexes
    where schemaname = 'public'
      and tablename = 'findings'
      and indexname = 'findings_scan_id_id_idx'
      and indexdef = 'CREATE UNIQUE INDEX findings_scan_id_id_idx ON public.findings USING btree (scan_id, id)'
  ),
  'findings has the exact unique key required by the composite foreign key'
);
select ok(
  exists (
    select 1
    from pg_constraint
    where conrelid = 'public.finding_ai_explanations'::regclass
      and contype = 'u'
      and pg_get_constraintdef(oid) = 'UNIQUE (finding_id)'
  ),
  'each finding has at most one AI explanation'
);
select ok(
  exists (
    select 1
    from pg_constraint c
    where c.conrelid = 'public.finding_ai_explanations'::regclass
      and c.confrelid = 'public.findings'::regclass
      and c.contype = 'f'
      and c.confdeltype = 'c'
      and (
        select array_agg(a.attname::text order by key_column.ordinality)
        from unnest(c.conkey) with ordinality as key_column(attnum, ordinality)
        join pg_attribute a
          on a.attrelid = c.conrelid and a.attnum = key_column.attnum
      ) = array['scan_id', 'finding_id']::text[]
      and (
        select array_agg(a.attname::text order by key_column.ordinality)
        from unnest(c.confkey) with ordinality as key_column(attnum, ordinality)
        join pg_attribute a
          on a.attrelid = c.confrelid and a.attnum = key_column.attnum
      ) = array['scan_id', 'id']::text[]
  ),
  'AI explanations retain the composite same-scan finding foreign key'
);
select ok(
  (
    select count(*) = 2
    from pg_class
    where oid in (
      'public.scan_ai_summaries'::regclass,
      'public.finding_ai_explanations'::regclass
    )
      and relrowsecurity
  ),
  'both AI guidance tables retain row-level security'
);
select ok(
  exists (
    select 1
    from pg_policy
    where polrelid = 'public.scan_ai_summaries'::regclass
      and polname = 'scan_ai_summaries_read_for_owned_scans'
      and 'authenticated'::regrole::oid = any (polroles)
      and pg_get_expr(polqual, polrelid) like '%scans.user_id%'
  )
  and exists (
    select 1
    from pg_policy
    where polrelid = 'public.finding_ai_explanations'::regclass
      and polname = 'finding_ai_explanations_read_for_owned_scans'
      and 'authenticated'::regrole::oid = any (polroles)
      and pg_get_expr(polqual, polrelid) like '%scans.user_id%'
      and pg_get_expr(polqual, polrelid) like '%findings.scan_id%'
  ),
  'AI guidance reads remain restricted to the owning user and scan'
);

insert into auth.users (id, email, raw_user_meta_data)
values
  ('dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'phase5-owner@example.test', '{}'),
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'phase5-other@example.test', '{}');

insert into public.scans (id, user_id, target_url, status)
values
  ('ffffffff-ffff-4fff-8fff-ffffffffffff', 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'https://phase5-owner.example.test', 'completed'),
  ('99999999-9999-4999-8999-999999999999', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'https://phase5-other.example.test', 'completed');

insert into public.findings (
  id, scan_id, check_id, title, severity, status, description, recommendation
)
values (
  '88888888-8888-4888-8888-888888888888',
  'ffffffff-ffff-4fff-8fff-ffffffffffff',
  'headers.hsts', 'HSTS missing', 'medium', 'fail', 'No HSTS header.', 'Configure HSTS.'
);

select throws_ok(
  $$insert into public.finding_ai_explanations (
      scan_id, finding_id, explanation, evidence_hash, provider, model, prompt_version
    ) values (
      '99999999-9999-4999-8999-999999999999',
      '88888888-8888-4888-8888-888888888888',
      '{}', repeat('a', 64), 'openai-compatible', 'test-model', '1.0'
    )$$,
  '23503',
  null,
  'the composite foreign key rejects a finding paired with another scan'
);

insert into public.finding_ai_explanations (
  scan_id, finding_id, explanation, evidence_hash, provider, model, prompt_version
)
values (
  'ffffffff-ffff-4fff-8fff-ffffffffffff',
  '88888888-8888-4888-8888-888888888888',
  '{}', repeat('b', 64), 'openai-compatible', 'test-model', '1.0'
);

select throws_ok(
  $$insert into public.finding_ai_explanations (
      scan_id, finding_id, explanation, evidence_hash, provider, model, prompt_version
    ) values (
      'ffffffff-ffff-4fff-8fff-ffffffffffff',
      '88888888-8888-4888-8888-888888888888',
      '{}', repeat('c', 64), 'openai-compatible', 'test-model', '1.0'
    )$$,
  '23505',
  null,
  'the unique finding_id constraint rejects duplicate explanations'
);

select * from finish();
rollback;
