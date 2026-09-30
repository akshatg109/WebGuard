begin;
select plan(39);

select ok((select relrowsecurity from pg_class where oid = 'public.profiles'::regclass), 'profiles has RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.scan_checks'::regclass), 'scan_checks has RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.scans'::regclass), 'scans has RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.findings'::regclass), 'findings has RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.technologies'::regclass), 'technologies has RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.scan_check_results'::regclass), 'scan_check_results has RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.scan_ai_summaries'::regclass), 'scan_ai_summaries has RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.finding_ai_explanations'::regclass), 'finding_ai_explanations has RLS enabled');

select ok(not has_table_privilege('anon', 'public.scans', 'select'), 'anon cannot read scans');
select ok(not has_table_privilege('anon', 'public.findings', 'select'), 'anon cannot read findings');
select ok(not has_table_privilege('anon', 'public.scan_check_results', 'select'), 'anon cannot read scan check results');
select ok(not has_table_privilege('anon', 'public.scan_ai_summaries', 'select'), 'anon cannot read AI summaries');
select ok(not has_table_privilege('anon', 'public.finding_ai_explanations', 'select'), 'anon cannot read AI explanations');
select ok(not has_table_privilege('authenticated', 'public.scans', 'insert'), 'users cannot create scans outside the API');
select ok(not has_table_privilege('authenticated', 'public.scans', 'update'), 'users cannot modify scan results');
select ok(not has_table_privilege('authenticated', 'public.findings', 'insert,update,delete'), 'users cannot modify findings');
select ok(not has_table_privilege('authenticated', 'public.scan_ai_summaries', 'insert,update,delete'), 'users cannot modify AI summaries');
select ok(not has_table_privilege('authenticated', 'public.finding_ai_explanations', 'insert,update,delete'), 'users cannot modify AI explanations');
select ok(not has_table_privilege('authenticated', 'public.technologies', 'insert,update,delete'), 'users cannot modify technologies');
select ok(has_table_privilege('service_role', 'public.scans', 'select,insert,update,delete'), 'server role has controlled persistence grants');
select ok(has_table_privilege('service_role', 'public.scan_check_results', 'select,insert,update,delete'), 'server role can persist scan check results');
select ok(has_table_privilege('service_role', 'public.scan_ai_summaries', 'select,insert,update,delete'), 'server role can persist AI summaries');
select ok(has_table_privilege('service_role', 'public.finding_ai_explanations', 'select,insert,update,delete'), 'server role can persist AI explanations');

insert into auth.users (id, email, raw_user_meta_data)
values
  ('11111111-1111-4111-8111-111111111111', 'owner@example.test', '{}'),
  ('22222222-2222-4222-8222-222222222222', 'other@example.test', '{}');

insert into public.scans (id, user_id, target_url, status)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '11111111-1111-4111-8111-111111111111', 'https://owner.example.test', 'completed'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', '22222222-2222-4222-8222-222222222222', 'https://other.example.test', 'completed');

insert into public.findings (scan_id, check_id, title, severity, status, description, recommendation)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'hsts', 'HSTS missing', 'medium', 'fail', 'No HSTS header was observed.', 'Configure HSTS after HTTPS is verified.'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'csp', 'CSP missing', 'medium', 'fail', 'No CSP header was observed.', 'Define a suitable CSP.');

insert into public.technologies (scan_id, name, category, confidence)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Example framework', 'framework', 0.900),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Other framework', 'framework', 0.800);

insert into public.scan_check_results (
  scan_id, check_id, status, severity, scoring_relevant, scoring_version,
  check_version, reason, evidence, score_explanation
)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'headers.hsts', 'fail', 'medium', true, '1.0', '1', 'HSTS absent.', '{}', '{}'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'headers.csp', 'fail', 'medium', true, '1.0', '1', 'CSP absent.', '{}', '{}');

insert into public.scan_ai_summaries (scan_id, summary, evidence_hash, provider, model, prompt_version)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '{"posture":"Owner summary"}', repeat('a', 64), 'openai-compatible', 'test-model', '1.0'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', '{"posture":"Other summary"}', repeat('b', 64), 'openai-compatible', 'test-model', '1.0');

insert into public.finding_ai_explanations (
  scan_id, finding_id, explanation, evidence_hash, provider, model, prompt_version
)
select findings.scan_id, findings.id, '{"what_it_means":"Owner explanation"}', repeat('c', 64), 'openai-compatible', 'test-model', '1.0'
from public.findings
where findings.scan_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' and findings.check_id = 'hsts';

insert into public.finding_ai_explanations (
  scan_id, finding_id, explanation, evidence_hash, provider, model, prompt_version
)
select findings.scan_id, findings.id, '{"what_it_means":"Other explanation"}', repeat('d', 64), 'openai-compatible', 'test-model', '1.0'
from public.findings
where findings.scan_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' and findings.check_id = 'csp';

set local role authenticated;
set local request.jwt.claim.sub = '11111111-1111-4111-8111-111111111111';

select results_eq(
  $$select count(*)::bigint from public.scans$$,
  array[1::bigint],
  'a user sees only their own scans'
);
select results_eq(
  $$select count(*)::bigint from public.findings$$,
  array[1::bigint],
  'a user sees findings only for their own scans'
);
select results_eq(
  $$select count(*)::bigint from public.technologies$$,
  array[1::bigint],
  'a user sees technologies only for their own scans'
);
select results_eq(
  $$select count(*)::bigint from public.scan_checks$$,
  array[24::bigint],
  'authenticated users can read the preserved and canonical check catalog'
);
select results_eq(
  $$select count(*)::bigint from public.scan_check_results$$,
  array[1::bigint],
  'a user sees check results only for their own scans'
);
select results_eq(
  $$select count(*)::bigint from public.scan_ai_summaries$$,
  array[1::bigint],
  'a user sees AI summaries only for their own scans'
);
select results_eq(
  $$select count(*)::bigint from public.finding_ai_explanations$$,
  array[1::bigint],
  'a user sees AI explanations only for findings in their own scans'
);
select results_eq(
  $$select email from public.profiles where id = '11111111-1111-4111-8111-111111111111'$$,
  array['owner@example.test'::text],
  'Auth signup creates the matching owner profile'
);
select is_empty(
  $$delete from public.scans where id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' returning id$$,
  'a user cannot delete another user scan'
);
select results_eq(
  $$update public.profiles set display_name = 'Owner' where id = '11111111-1111-4111-8111-111111111111' returning display_name$$,
  array['Owner'::text],
  'a user can update their own profile'
);

set local request.jwt.claim.sub = '22222222-2222-4222-8222-222222222222';
select results_eq(
  $$select count(*)::bigint from public.scans$$,
  array[1::bigint],
  'another user sees only their own scans'
);
select results_eq(
  $$select title from public.findings$$,
  array['CSP missing'::text],
  'another user sees only findings for their own scans'
);
select results_eq(
  $$select name from public.technologies$$,
  array['Other framework'::text],
  'another user sees only technologies for their own scans'
);
select results_eq(
  $$select check_id from public.scan_check_results$$,
  array['headers.csp'::text],
  'another user sees only check results for their own scans'
);
select results_eq(
  $$select summary->>'posture' from public.scan_ai_summaries$$,
  array['Other summary'::text],
  'another user sees only their scan AI summary'
);
select results_eq(
  $$select explanation->>'what_it_means' from public.finding_ai_explanations$$,
  array['Other explanation'::text],
  'another user sees only their finding AI explanation'
);

select * from finish();
rollback;
