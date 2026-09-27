# WebGuard — UI/UX Design Direction

## 1. Design Goal

WebGuard should look like a premium modern cybersecurity SaaS product.

Desired characteristics:
- dark
- professional
- technical
- clean
- information-dense but readable
- trustworthy
- polished
- responsive

Avoid:
- excessive neon
- generic AI gradients
- excessive glassmorphism
- clutter
- overly decorative dashboards

## 2. Visual System

### Background
Very dark neutral background.

### Surfaces
Slightly lighter neutral cards with subtle borders.

### Accent
Use one primary accent for interactive elements.

### Severity
Use semantic colors consistently:
- Critical: red
- High: orange/red
- Medium: amber
- Low: blue
- Informational: neutral
- Passed: green

Do not rely on color alone; include labels/icons.

## 3. Typography

Use a modern sans-serif for general UI.

Use monospace selectively for:
- URLs
- HTTP headers
- technical values
- code-like evidence

## 4. Main Navigation

Desktop:
```text
WebGuard
────────────────────────
Overview
Scans
Reports
Settings
────────────────────────
User
```

Mobile:
- compact header
- navigation drawer/sheet

## 5. Pages

### Landing
Sections:
1. Hero
2. Scan input
3. Security checks overview
4. Example report
5. Features
6. How it works
7. CTA
8. Footer

Hero CTA:
`Scan a Website`

Include authorization notice near scan functionality.

### Login
Simple, focused authentication page.

### Dashboard
Show:
- total scans
- latest score
- average score
- recent targets
- recent scans
- quick scan action

### New Scan
Large URL input.

Include:
- HTTPS recommendation
- authorization notice
- validation
- clear scan button

### Scan Results
Top:
- target URL
- timestamp
- score
- scan status

Then:
- score visualization
- severity summary
- findings
- passed checks
- technologies
- recommendations

### Finding Detail
Show:
- severity
- title
- explanation
- observed evidence
- why it matters
- remediation
- references when appropriate

### Scan History
Table/list with:
- target
- date
- score
- status
- action

### Settings
- profile
- security
- account

## 6. Dashboard Components

Suggested reusable components:
- `SecurityScore`
- `SeverityBadge`
- `FindingCard`
- `FindingTable`
- `ScanStatus`
- `ScanHistoryTable`
- `TechnologyList`
- `SecurityMetric`
- `EmptyState`
- `ErrorState`
- `LoadingSkeleton`

## 7. Interaction Design

Use:
- subtle hover states
- clear focus states
- short transitions
- skeleton loading
- toast notifications for actions
- confirmation for destructive actions

Avoid animation that slows down security workflows.

## 8. Responsive Behavior

Desktop:
- sidebar
- multi-column dashboard
- dense results layout

Tablet:
- collapsible sidebar
- two-column cards where appropriate

Mobile:
- single-column cards
- horizontally scrollable tables where necessary
- large scan input
- touch-friendly controls

## 9. Accessibility

Must include:
- keyboard navigation
- visible focus states
- semantic HTML
- proper labels
- sufficient contrast
- accessible dialogs
- screen-reader-friendly status messages

## 10. Premium Details

Use:
- consistent 8px spacing system
- subtle borders
- clean cards
- strong typography hierarchy
- empty states with useful explanations
- polished loading states
- concise microcopy

The product should feel closer to a commercial developer/security platform than a university assignment.
