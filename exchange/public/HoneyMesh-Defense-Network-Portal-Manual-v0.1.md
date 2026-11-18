# HoneyMesh Defense Network Portal Manual

Version: 0.1
Updated: 2026-03-23

## Purpose

The HoneyMesh Defense Network Portal is the control plane for the HoneyMesh community exchange.

It is used for:

- tenant admin login
- license activation and validation
- HoneyMesh node registration
- Trusted Network Sharing controls
- reviewing recent blocked threats
- publishing sanitized stopped-attack signals
- receiving approved community protection
- auditing moderation and sync behavior

HoneyMesh remains endpoint-first. The portal does not replace local enforcement. It coordinates trusted intelligence exchange and operator visibility while each HoneyMesh node remains sovereign over local policy.

## Core Product Model

The HoneyMesh Exchange is a Pro-only control plane.

Community users do not create Exchange accounts and do not log in to the Exchange.

Exchange access is reserved for active Pro licenses and includes:

- portal access for tenant admins and reviewers
- Trusted Network Sharing controls
- publish of sanitized stopped-attack signals
- pull of approved community signals
- review and moderation workflows
- node registration and sync visibility

## Privacy and Data Sharing

HoneyMesh shares only sanitized, defensive intelligence derived from blocked attacks.

It does not share:

- raw payloads
- internal hostnames
- internal topology
- customer secrets
- cookies or request bodies by default

The exchange is designed to share only the minimum threat signal required to identify and stop similar attacks across the network.

## Human Access Model

The portal uses human login for people and separate machine authentication for HoneyMesh nodes.

### Roles

- `super_admin`: platform owner and highest-privilege operator
- `tenant_admin`: manages tenant settings, licenses, sharing, and nodes
- `reviewer`: approves or rejects submitted signals
- `analyst`: read-only visibility into tenant intelligence

### Login Flow

1. Open `/login`
2. Enter email and password
3. Complete MFA if required
4. Receive a secure session cookie
5. Enter the portal dashboard

Sensitive actions should be limited to `super_admin` and `tenant_admin`.

## Tenant Onboarding

### Register a New Tenant

1. Open the registration flow
2. Upload a valid `license.json`
3. Create the tenant admin account
4. Create the organization / tenant

### Pro Signup

Exchange signup requires:

- organization name
- admin name
- admin email
- password
- valid `license.json`

The portal validates the license before the tenant is created.

The portal checks:

- signature validity
- expiration
- license tier is `pro`
- tenant binding
- duplicate claim state by license fingerprint

If validation succeeds:

- the tenant is created as Pro
- Exchange access is activated
- Trusted Network Sharing remains off by default

If validation fails:

- the tenant is not created
- Exchange access is denied
- the user should be directed to pricing or renewal

### License Activation

Licenses are validated server-side only.

The portal checks:

- signature validity
- expiration
- license tier
- tenant binding

Community users should remain in the HoneyMesh app and pricing flow rather than the Exchange.

## Trusted Network Sharing

Trusted Network Sharing is:

- Pro-only
- off by default
- explicitly opt-in
- disabled immediately if Pro becomes invalid or expires

When Trusted Network Sharing is off:

- HoneyMesh nodes cannot publish signals
- HoneyMesh nodes cannot pull community signals

When Trusted Network Sharing is on:

- eligible Pro nodes can publish sanitized signals
- eligible Pro nodes can pull approved community protection

## Node Registration

HoneyMesh nodes do not log in as users.

They register through an enrollment flow.

### Registration Steps

1. Tenant admin opens the Nodes area
2. Admin generates an enrollment token
3. Token is provided to the HoneyMesh node
4. The node registers with:
   - enrollment token
   - node name
   - cluster ID
   - software version
   - public key
5. The portal validates the token and stores the node record
6. The token is marked used

### Node Identity

Every registered node has:

- `node_id`
- `tenant_id`
- cluster association
- public key
- shared secret or request-signing material
- last seen status

Nodes can be revoked at any time by an authorized admin.

## Machine API Model

HoneyMesh nodes communicate with the portal through dedicated APIs.

### Main Node Endpoints

- `POST /api/hm/publish-ban`
- `GET /api/hm/community-bans`
- `POST /api/hm/heartbeat`
- `POST /api/hm/ban-feedback`
- `GET /api/hm/config`

### Request Security

Node requests are protected with:

- node identity
- request signatures
- timestamp freshness
- nonce replay protection
- per-IP, per-node, and per-tenant rate limits

## Publish Flow

When HoneyMesh blocks or stages a threat locally:

1. The node creates a sanitized signal
2. The request is signed
3. The portal validates:
   - node identity
   - signature
   - timestamp
   - nonce
   - tenant entitlement
   - sharing state
   - payload schema
   - duplicate evidence hash
   - rate limits
4. The portal routes the signal into one of the moderation lanes

### Moderation Lanes

- `auto_approve`
- `pending_review`
- `quarantined`
- `reject`

Signals may be quarantined if trust is low or the exchange is in review-only mode.

## Pull Flow

HoneyMesh nodes pull community intelligence using a cursor-based feed.

### How It Works

1. The node requests `GET /api/hm/community-bans?since=<cursor>`
2. The portal validates the node and tenant
3. The portal returns approved community signals only
4. The node applies local policy
5. The node stores the returned cursor for the next sync

### Local Policy

HoneyMesh still decides locally whether to:

- observe only
- suggest
- temporary enforce
- auto-enforce high-confidence only

The portal never removes endpoint sovereignty.

## Dashboard

The first main operator view is the `Last 500 Blocks` dashboard.

### Main Metrics

- Total Blocks (24h)
- Unique Attackers
- Top Attack Type
- Top JA4
- Local Blocks
- Network Blocks

### Recent Defense Activity Table

Columns:

- Time
- Attacker IP
- Port / Service
- JA4
- Attack Type
- Source
- Action

Source values:

- `LOCAL`
- `NETWORK`

### Privacy Note

The dashboard shows sanitized threat indicators only.

## Review Queue

The review area shows signals that are:

- `pending`
- `quarantined`

Reviewers can:

- approve
- reject

Every moderation action is written to the audit log.

## Settings

The Settings page exposes tenant-level exchange state.

### Current Tenant State

- plan
- license status
- license expiry
- sharing enabled
- exchange kill switch
- review-only mode
- auto-approve enabled
- trust level
- local policy mode
- quarantined signal count
- rejected signal count

### Exchange Controls

Authorized admins can update:

- Trusted Network Sharing
- Exchange Kill Switch
- Review-Only Mode
- Auto-Approve
- Local Policy Mode

## Kill Switches

The portal supports hard containment controls.

### Exchange Kill Switch

When enabled:

- community exchange is stopped for the tenant
- node publish is blocked
- node pull is blocked

### Review-Only Mode

When enabled:

- auto-approval is suppressed
- eligible submissions move into review instead

### Auto-Approve Toggle

When disabled:

- even trusted signals do not auto-approve
- review becomes the primary moderation path

## Audit Logging

All important actions should appear in audit logs, including:

- login/logout
- MFA challenge generation
- node registration
- node revoke
- license upload
- publish acceptance or rejection
- moderation decisions
- pull activity
- heartbeat events
- settings changes

The portal also records reason codes for many exchange decisions.

Examples:

- `auth.invalid_signature`
- `auth.replay_detected`
- `auth.community_feed_not_allowed`
- `schema.invalid_payload`
- `exchange.rate_limited`
- `exchange.duplicate_signal`
- `exchange.quarantined`
- `exchange.approved`

## Security Controls

Current security model includes:

- secure session cookies
- MFA-capable login flow
- server-side license validation
- signed node requests
- timestamp freshness checks
- nonce replay protection
- duplicate suppression
- tenant-scoped object authorization
- rate limiting
- audit logging

## Operational Guidance

### When to Enable Trusted Network Sharing

Enable it only after:

- Pro license is active
- node registration is complete
- local policy mode is understood
- reviewers know how to use the queue

### Recommended Policy Choices

- conservative environments: `audit_only`
- balanced environments: `suggested`
- aggressive temporary enforcement: `auto_temp`
- strongest automated posture: `auto_high_confidence`

### Recommended Review Practice

Review:

- quarantined submissions first
- repeated attacker clusters
- high-confidence JA4 correlations
- noisy contributors with low trust

## Troubleshooting

### Node Cannot Publish

Check:

- tenant is Pro
- sharing is enabled
- exchange kill switch is off
- node is not revoked
- timestamp and nonce are valid
- payload schema is valid
- node is not rate-limited

### Node Cannot Pull Community Bans

Check:

- tenant is Pro
- sharing is enabled
- exchange kill switch is off
- node request signature is valid
- request is using the correct cursor and auth headers

### License Upload Fails

Check:

- JSON is valid
- signature is correct
- license is not expired
- license belongs to the correct tenant

### Signals Stay Pending or Quarantined

Check:

- tenant review-only mode
- auto-approve setting
- node trust level
- confidence level
- duplicate or abuse conditions

## Current Architecture Notes

The current portal is:

- built on Next.js App Router
- durable database-backed
- local SQLite-backed in this environment
- ready to migrate to PostgreSQL cleanly

Future production upgrades should include:

- PostgreSQL
- PgBouncer
- Redis for shared nonce/rate-limit state
- background workers for heavy trust/analytics jobs
- stronger step-up auth for sensitive admin actions

## Operator Summary

Use the portal to:

1. sign in as an authorized operator
2. validate the tenant license
3. register HoneyMesh nodes
4. enable Trusted Network Sharing only if desired
5. monitor the last 500 blocks
6. review pending or quarantined signals
7. use kill switches when containment is needed

HoneyMesh remains local-first. The portal adds trusted coordination, moderation, and visibility without exposing sensitive internal data.
