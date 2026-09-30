begin;
select plan(18);

select is(
  (select count(*)::integer from public.scan_checks where is_canonical),
  13,
  'all current scanner IDs have canonical catalog rows'
);
select is(
  (select count(*)::integer from public.scan_checks where not is_canonical),
  11,
  'all legacy catalog rows are preserved'
);
select is(
  (select count(*)::integer from public.scan_checks),
  24,
  'legacy and canonical rows coexist without duplicates'
);
select is(
  (select count(*)::integer from public.scan_checks where is_canonical and legacy_check_id is not null),
  11,
  'all legacy-to-canonical correspondences are explicit'
);
select is(
  (select category from public.scan_checks where check_id = 'exposure.server_headers'),
  'exposure'::text,
  'canonical server-header exposure has the canonical category'
);
select is(
  (select legacy_check_id from public.scan_checks where check_id = 'exposure.server_headers'),
  'server_header'::text,
  'legacy server-header ID is retained only as reconciliation metadata'
);

select ok(
  (select pg_get_constraintdef(oid) like '%pass%' and pg_get_constraintdef(oid) like '%fail%'
     and pg_get_constraintdef(oid) like '%warn%' and pg_get_constraintdef(oid) like '%not_applicable%'
     and pg_get_constraintdef(oid) like '%error%'
   from pg_constraint where conrelid = 'public.findings'::regclass and conname = 'findings_status_check'),
  'findings status constraint includes the five scanner statuses'
);
select ok(
  (select pg_get_constraintdef(oid) like '%pass%' and pg_get_constraintdef(oid) like '%fail%'
     and pg_get_constraintdef(oid) like '%warn%' and pg_get_constraintdef(oid) like '%not_applicable%'
     and pg_get_constraintdef(oid) like '%error%'
   from pg_constraint where conrelid = 'public.scan_check_results'::regclass
     and conname = 'scan_check_results_status_check'),
  'scan check results constrain status to the five scanner values'
);
select ok(
  (select pg_get_constraintdef(oid) like '%pending%' and pg_get_constraintdef(oid) like '%running%'
     and pg_get_constraintdef(oid) like '%completed%' and pg_get_constraintdef(oid) like '%failed%'
   from pg_constraint where conrelid = 'public.scans'::regclass and conname = 'scans_status_check'),
  'scan lifecycle is limited to pending, running, completed, and failed'
);
select ok(
  (select relrowsecurity from pg_class where oid = 'public.scan_check_results'::regclass),
  'scan check results have RLS enabled'
);
select ok(
  has_table_privilege('service_role', 'public.scan_check_results', 'select,insert,update,delete'),
  'server role has persistence privileges for check results'
);
select ok(
  not has_table_privilege('authenticated', 'public.scan_check_results', 'insert,update,delete'),
  'authenticated clients cannot write check results directly'
);
select ok(
  has_function_privilege(
    'service_role',
    'public.persist_completed_scan(uuid,uuid,text,smallint,boolean,text,text,jsonb,timestamptz,integer,jsonb,jsonb,jsonb)',
    'execute'
  ),
  'service role can call the atomic completion function'
);
select ok(
  not has_function_privilege(
    'authenticated',
    'public.persist_completed_scan(uuid,uuid,text,smallint,boolean,text,text,jsonb,timestamptz,integer,jsonb,jsonb,jsonb)',
    'execute'
  ),
  'authenticated clients cannot call the privileged completion function'
);
select ok(
  not has_function_privilege(
    'anon',
    'public.persist_completed_scan(uuid,uuid,text,smallint,boolean,text,text,jsonb,timestamptz,integer,jsonb,jsonb,jsonb)',
    'execute'
  ),
  'anonymous clients cannot call the privileged completion function'
);
select ok(
  not (select prosecdef from pg_proc
       where oid = 'public.persist_completed_scan(uuid,uuid,text,smallint,boolean,text,text,jsonb,timestamptz,integer,jsonb,jsonb,jsonb)'::regprocedure),
  'completion function does not elevate privileges'
);

insert into auth.users (id, email, raw_user_meta_data)
values ('33333333-3333-4333-8333-333333333333', 'schema-test@example.test', '{}');
insert into public.scans (id, user_id, target_url, status)
values (
  'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  '33333333-3333-4333-8333-333333333333',
  'https://schema-test.example.test',
  'completed'
);

set local role service_role;
select throws_ok(
  $$insert into public.scan_check_results (
      scan_id, check_id, status, scoring_relevant, scoring_version,
      check_version, reason, evidence, score_explanation
    ) values (
      'cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'headers.hsts', 'arbitrary',
      true, '1.0', '1', 'bad', '{}', '{}'
    )$$,
  '23514',
  null,
  'scan check results reject arbitrary status strings'
);
select throws_ok(
  $$insert into public.findings (
      scan_id, check_id, title, severity, status, description, recommendation
    ) values (
      'cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'headers.hsts', 'bad',
      'medium', 'arbitrary', 'bad', 'bad'
    )$$,
  '23514',
  null,
  'findings reject arbitrary status strings'
);

select * from finish();
rollback;
