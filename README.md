# SecComply ISMS v9 — Security-Hardened Edition

## Defense-in-Depth Architecture

```
LAYER 1: BROWSER SECURITY
  CSP, HSTS, X-Frame-Options DENY, Permissions-Policy,
  Print watermark, Console social engineering warning, Cache-Control no-store

LAYER 2: APPLICATION SECURITY
  Input sanitization, Password complexity (12+ mixed), Force password change,
  Progressive login cooldown, 30-min idle timeout, 8-hour max session,
  Server-side logout, File magic byte verification, Export watermarking,
  Double confirm critical deletes, Type-to-confirm org deletion, Screen watermark

LAYER 3: API SECURITY (Edge Functions)
  service_role key server-side only, JWT caller verification,
  Role hierarchy enforcement, Rate limiting (10/hr), Input sanitization,
  Email format validation, Org-scoped permissions, Failed op audit logging

LAYER 4: DATABASE SECURITY
  RLS on ALL tables (org-scoped), Immutable audit_log (no UPDATE/DELETE),
  Auto-audit triggers, Account lockout tracking, SHA-256 data checksums,
  Session tracking, Private storage + MIME allowlist + 50MB limit

LAYER 5: INFRASTRUCTURE
  HSTS preload, CORS, Cross-Origin-Opener/Embedder/Resource Policies,
  Supabase rate limits, .env excluded from Git
```

## Vulnerability Fixes (18 original + 20 new features)

| # | Issue | CVSS | Fix |
|---|---|---|---|
| V1 | Client-side-only auth | 9.8 | RLS on all tables, org-scoped |
| V2 | RBAC as writable JSON | 9.1 | user_org_roles table with RLS |
| V3 | Hardcoded credentials | 8.6 | Environment variables |
| V4 | Weak passwords | 7.5 | crypto API + complexity rules |
| V5 | Public storage | 8.2 | Private bucket + signed URLs |
| V6 | Super admin backdoor | 9.1 | Removed entirely |
| V7 | No token refresh | 5.3 | Auto-refresh before expiry |
| V8 | No session timeout | 6.1 | 30-min idle + 8-hour max |
| V9 | No file validation | 7.4 | Extension + magic bytes + 50MB |
| V10 | Hardcoded admin email | 4.3 | VITE_SUPER_ADMIN_EMAIL |
| V11 | Predictable IDs | 5.3 | crypto.randomUUID() |
| V13 | No rate limiting | 7.5 | Client + Edge Function limits |
| V14 | Error info leak | 5.3 | Generic messages |
| V15 | Missing headers | 5.0 | Full CSP+HSTS+CORP+COOP+COEP |
| V16 | iframe sandbox | 4.3 | Strict sandbox + referrerPolicy |
| V17 | No input sanitization | 6.1 | XSS prevention on all inputs |

## New Security Features (SEC-1 through SEC-20)

| ID | Feature | Description |
|---|---|---|
| SEC-1 | Password Complexity | 12+ chars, mixed case, number, special, no patterns |
| SEC-2 | Audit Trail | Immutable DB log: logins, exports, changes, uploads |
| SEC-3 | Data Integrity | SHA-256 checksums on saved compliance data |
| SEC-4 | MIME Verification | Magic byte detection blocks disguised files |
| SEC-5 | Session Management | 30-min idle timeout + 8-hour max + warning |
| SEC-6 | Export Watermark | All exports stamped with user + timestamp |
| SEC-7 | Server Logout | JWT invalidated server-side |
| SEC-8 | Session Fingerprint | Browser fingerprint for anomaly detection |
| SEC-9 | Force Password Change | Must change on first login |
| SEC-10 | Screen Watermark | Subtle overlay with logged-in identity |
| SEC-11 | Timeout Warning | "Session expiring" banner with extend |
| SEC-12 | Tab Monitoring | Audit log on tab switch |
| SEC-13 | Login Cooldown | Progressive delay after failures |
| SEC-14 | Enhanced CSP | frame-ancestors none, upgrade-insecure |
| SEC-15 | Permissions Policy | Camera/mic/geo/payment all disabled |
| SEC-16 | Print Protection | CONFIDENTIAL watermark when printed |
| SEC-17 | CSS No-Select | Prevents selection of sensitive badges |
| SEC-19 | DevTools Warning | Console warning vs social engineering |
| SEC-20 | Cache Control | No-store prevents browser caching |

## Setup

### 1. Environment Variables (.env)
```
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-key
VITE_SUPER_ADMIN_EMAIL=admin@yourcompany.com
```

### 2. Database — Run supabase_setup_v8.sql in SQL Editor

### 3. Edge Function
```bash
supabase secrets set SERVICE_ROLE_KEY=your-service-role-key
supabase functions deploy create-user
```

### 4. Supabase Dashboard
- Auth → Rate Limits: sign-in 5/min, signup 3/hour
- Auth → Settings: min password 12, enable leaked password protection

### 5. Run
```bash
npm install && npm run dev
```
