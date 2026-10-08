# Garuda Mail Product Design

## 1. Design Direction

Garuda Mail is a security operations mailbox: dense, calm, and evidence-oriented. The interface should prioritize scanning and decisive actions over decorative surfaces. Visual language combines dark operational navigation with high-contrast status colors and clear transport-security metadata.

## 2. Information Architecture

- Login and registration
- Inbox
- Message detail
- Compose and draft editing
- Sent
- Starred
- Archive
- Trash
- Analysis and findings
- Forensic sessions
- CBOM and certificate views
- Settings

The primary navigation keeps mailbox folders above analytical workspaces. Settings contains transport profiles, protocol information, and connection verification.

## 3. Core Flows

### Sign in

1. User enters email and password or chooses a seeded development account.
2. The form shows an inline error for invalid credentials.
3. Successful sign-in redirects to the inbox.
4. The top bar displays the current identity and sign-out action.

### Read and triage

1. Inbox shows sender, subject, preview, timestamp, unread state, star state, and security indicators.
2. User selects a row to open message detail.
3. Detail view exposes body, recipients, transport protocol, TLS version, cipher, PFS, and risk score.
4. User can reply, forward, star, archive, or trash without losing context.

### Compose and deliver

1. Compose opens as a focused workspace with recipient chips, subject, body, and optional Cc.
2. Protocol selection is a segmented control or menu with port and encryption details.
3. A security summary shows the selected transport and forward secrecy state.
4. Send provides immediate progress and then a delivery result with message id and transcript access.
5. Save draft is available without requiring a successful external SMTP connection.

### Configure transport

1. Settings lists protocol profiles and current readiness.
2. SMTP configuration fields are masked and never echoed into logs.
3. Verify connection reports success or a safe diagnostic message.
4. The UI distinguishes configured, verified, unavailable, and simulated states.

## 4. Visual System

### Color semantics

- Cyan: active navigation, secure information, primary focus.
- Green: verified, delivered, TLS/PFS healthy.
- Amber: warning, opportunistic TLS, configuration incomplete.
- Red: critical risk, failed delivery, destructive action.
- Slate/charcoal: navigation and work surfaces.
- White/light slate: readable content surfaces and message body.

Colors must not be the only status signal; pair them with labels, icons, or text.

### Typography

Use the existing project font and typography tokens consistently. Headings should establish hierarchy without competing with message subjects. Body text must remain readable at normal zoom and support long forensic content.

### Components

- Sidebar: persistent desktop navigation, collapsible on smaller screens.
- Top bar: current user, search, notifications, and primary compose action.
- Mail row: fixed-height scanning unit with sender, subject, preview, date, and status icons.
- Security badge: compact protocol/TLS/PFS indicator with a tooltip or expanded detail.
- Compose panel: stable layout with explicit send, save draft, and cancel actions.
- Transcript panel: monospace log with copy/export affordance and clear simulated/confirmed labeling.
- Settings section: grouped form controls with independent save and verify actions.

## 5. Responsive Behavior

- Desktop: sidebar plus content workspace.
- Tablet: narrower sidebar or drawer, preserve message list scanning.
- Mobile: single-column navigation drawer, full-width compose, sticky primary action bar.
- Never allow long subjects, addresses, or protocol labels to break the layout; truncate with accessible full text.

## 6. Accessibility

- Every icon-only button has an accessible name.
- Focus order follows visual order.
- Forms expose labels and validation messages.
- Status is announced for send, save, and connection verification.
- Contrast meets WCAG AA for text and controls.
- Keyboard users can navigate mail rows, folders, dialogs, and transcript content.

## 7. Interaction Principles

- Make destructive actions explicit and reversible when possible.
- Keep success and failure feedback near the action that caused it.
- Preserve compose content on recoverable failures.
- Avoid hidden auto-actions that change mailbox state without a visible explanation.
- Polling should update lists without stealing focus or resetting the user's current selection.
