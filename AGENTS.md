# WebGuard — OpenCode Project Instructions

## Project
WebGuard is a production-style web security analysis platform for authorized security testing of websites.

## Primary goal
Build a polished, portfolio-quality application that demonstrates:
- Next.js and TypeScript
- Modern UI/UX
- Supabase/PostgreSQL
- Authentication and authorization
- REST APIs
- Python/FastAPI
- HTTP/TLS/security-header analysis
- Data visualization
- PDF reporting
- Deployment and production engineering

## Repository rules
- Read `docs/prd.md`, `docs/architecture.md`, `docs/design.md`, `docs/tasks.md`, and `docs/memory.md` before making substantial changes.
- Follow the architecture unless a documented decision changes it.
- Keep frontend, backend, and shared concerns clearly separated.
- Prefer small, maintainable components and functions.
- Use TypeScript with strict typing.
- Validate all user input at system boundaries.
- Never expose secrets or API keys to the client.
- Never hard-code credentials.
- Add useful error handling and loading states.
- Do not add dependencies unless they have a clear purpose.
- Update `docs/tasks.md` when completing or changing implementation work.
- Update `docs/memory.md` when an important architectural or product decision is made.

## Security rules
- WebGuard is for domains and systems the user owns or is explicitly authorized to test.
- Do not implement destructive exploitation, credential attacks, malware, persistence, or stealth features.
- Scanner features should focus on defensive configuration and passive/safe analysis.
- Protect against SSRF: validate targets, resolve and restrict unsafe/private destinations where appropriate, enforce timeouts, limit redirects, and avoid arbitrary internal network access.
- Apply rate limits and resource limits to scanning endpoints.
- Never log secrets, authorization headers, cookies, or sensitive user data unnecessarily.

## UI rules
- The interface should feel like a premium security SaaS product.
- Prefer clarity and hierarchy over visual clutter.
- Use accessible components, keyboard navigation, clear focus states, and responsive layouts.
- Use severity consistently: critical, high, medium, low, informational, passed.
- Avoid excessive gradients, unnecessary glassmorphism, and decorative UI that reduces readability.


## Frontend Skill Usage

WebGuard uses the globally installed OpenCode UI/UX skills as part of its frontend development workflow.

When implementing frontend features, actively apply the relevant installed skill(s) rather than creating generic UI patterns from scratch.

Installed UI/UX skills available globally include:
- `dashboard-layout`
- `design-tokens-theming`
- `component-architecture`
- `responsive-layout`
- `accessible-components`
- `navigation-patterns`
- `data-tables`
- `empty-and-loading-states`
- `notifications-and-toasts`
- `auth-screens`
- `settings-pages`
- `forms-and-validation`
- `modals-and-dialogs`
- `onboarding-flows`
- `billing-and-pricing`

### Skill selection rules
- Use `dashboard-layout` for dashboard structure and information hierarchy.
- Use `design-tokens-theming` for the visual system, spacing, typography, colors, and theme tokens.
- Use `component-architecture` for reusable UI components and component boundaries.
- Use `responsive-layout` for desktop/tablet/mobile behavior.
- Use `accessible-components` for keyboard navigation, focus states, semantics, and accessible interactions.
- Use `navigation-patterns` for sidebar, header, breadcrumbs, and application navigation.
- Use `data-tables` for scan history, findings, and other tabular data.
- Use `empty-and-loading-states` for skeletons, loading states, and empty states.
- Use `notifications-and-toasts` for success, error, and action feedback.
- Use `auth-screens` for login, signup, and authentication flows.
- Use `settings-pages` for account and application settings.
- Use `forms-and-validation` for scan forms, URL validation UI, and other user input.
- Use `modals-and-dialogs` for confirmations and focused dialogs.
- Use `onboarding-flows` where first-time user guidance is useful.
- Use `billing-and-pricing` only if WebGuard later introduces subscriptions or usage-based plans.

Always combine these skills with `docs/design.md` and the product requirements in `docs/prd.md`.

Do not blindly apply every skill to every feature. Select only the relevant skills for the task.

## Development workflow
1. Understand the relevant requirements.
2. Inspect existing code before editing.
3. Implement the smallest coherent change.
4. Run relevant checks/tests.
5. Fix errors.
6. Update task/context documentation when appropriate.
7. Summarize what changed and what remains.

## Definition of done
A feature is not complete merely because it renders. It should include appropriate validation, error handling, loading/empty states, responsive behavior, and tests where practical.
