begin;
select plan(21);

select ok((select relrowsecurity from pg_class where oid = 'public.profiles'::regclass), 'profiles has RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.scan_checks'::regclass), 'scan_checks has RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.scans'::regclass), 'scans has RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.findings'::regclass), 'findings has RLS enabled');
select ok((select relrowsecurity from pg_class where oid = 'public.technologies'::regclass), 'technologies has RLS enabled');

select ok(not has_table_privilege('anon', 'public.scans', 'select'), 'anon cannot read scans');
select ok(not has_table_privilege('anon', 'public.findings', 'select'), 'anon cannot read findings');
select ok(not has_table_privilege('authenticated', 'public.scans', 'insert'), 'users cannot create scans outside the API');
select ok(not has_table_privilege('authenticated', 'public.scans', 'update'), 'users cannot modify scan results');
select ok(not has_table_privilege('authenticated', 'public.findings', 'insert,update,delete'), 'users cannot modify findings');
select ok(not has_table_privilege('authenticated', 'public.technologies', 'insert,update,delete'), 'users cannot modify technologies');
select ok(has_table_privilege('service_role', 'public.scans', 'select,insert,update,delete'), 'server role has controlled persistence grants');

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
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'hsts', 'HSTS missing', 'medium', 'failed', 'No HSTS header was observed.', 'Configure HSTS after HTTPS is verified.'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'csp', 'CSP missing', 'medium', 'failed', 'No CSP header was observed.', 'Define a suitable CSP.');

insert into public.technologies (scan_id, name, category, confidence)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Example framework', 'framework', 0.900),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Other framework', 'framework', 0.800);

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
  array[11::bigint],
  'authenticated users can read the seeded global check catalog'
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

select * from finish();
rollback;
