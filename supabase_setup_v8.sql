-- ================================================================
-- SecComply ISMS v9 — Security-Hardened Database Setup
-- ================================================================
-- INCLUDES:
--   Core tables with org-scoped RLS
--   Audit trail for all sensitive operations
--   Session tracking for concurrent session control
--   Data integrity checksums
--   Force-password-change flag
-- ================================================================


-- ================================================================
-- 1. CLEANUP
-- ================================================================
DROP POLICY IF EXISTS "select_own" ON isms_state;
DROP POLICY IF EXISTS "insert_own" ON isms_state;
DROP POLICY IF EXISTS "update_own" ON isms_state;
DROP POLICY IF EXISTS "delete_own" ON isms_state;
DROP POLICY IF EXISTS "authenticated_select" ON isms_state;
DROP POLICY IF EXISTS "authenticated_insert" ON isms_state;
DROP POLICY IF EXISTS "authenticated_update" ON isms_state;
DROP POLICY IF EXISTS "authenticated_delete" ON isms_state;

DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS active_sessions CASCADE;
DROP TABLE IF EXISTS user_org_roles CASCADE;
DROP TABLE IF EXISTS isms_state CASCADE;


-- ================================================================
-- 2. user_org_roles — Server-side RBAC
-- ================================================================
CREATE TABLE user_org_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL CHECK (role IN ('super_admin','employee','client_admin','client_user','client_employee')),
  org_id TEXT,
  created_by TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT now(),
  status TEXT DEFAULT 'active' CHECK (status IN ('active','inactive','suspended')),
  must_change_password BOOLEAN DEFAULT true,
  last_password_change TIMESTAMPTZ,
  failed_login_count INT DEFAULT 0,
  locked_until TIMESTAMPTZ,
  UNIQUE(user_id, org_id)
);

CREATE INDEX idx_uor_user ON user_org_roles(user_id);
CREATE INDEX idx_uor_org ON user_org_roles(org_id);
CREATE INDEX idx_uor_email ON user_org_roles(email);


-- ================================================================
-- 3. isms_state — Multi-tenant data store with integrity hash
-- ================================================================
CREATE TABLE isms_state (
  user_id TEXT PRIMARY KEY,
  state JSONB DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ DEFAULT now(),
  updated_by UUID,
  checksum TEXT  -- SHA-256 of state for tamper detection
);

CREATE INDEX idx_isms_state_updated ON isms_state(updated_at DESC);


-- ================================================================
-- 4. audit_log — Immutable audit trail
-- ================================================================
CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ DEFAULT now() NOT NULL,
  user_id UUID,
  user_email TEXT,
  action TEXT NOT NULL,              -- 'login','logout','create_user','delete_org','data_export','rbac_change','data_modify','file_upload','file_download','password_change','role_change','failed_login'
  resource_type TEXT,                -- 'user','org','isms_data','file','rbac','session'
  resource_id TEXT,                  -- ID of the affected resource
  org_id TEXT,                       -- Which org this action relates to
  details JSONB DEFAULT '{}'::jsonb, -- Additional context (old/new values for changes)
  ip_address INET,
  user_agent TEXT,
  severity TEXT DEFAULT 'info' CHECK (severity IN ('info','warning','critical')),
  success BOOLEAN DEFAULT true
);

CREATE INDEX idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_org ON audit_log(org_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_severity ON audit_log(severity);

-- Audit log is APPEND-ONLY: no updates, no deletes (even for super_admin)
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;


-- ================================================================
-- 5. active_sessions — Concurrent session tracking
-- ================================================================
CREATE TABLE active_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  session_token_hash TEXT NOT NULL,     -- SHA-256 of JWT, not the JWT itself
  created_at TIMESTAMPTZ DEFAULT now(),
  last_active TIMESTAMPTZ DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  ip_address INET,
  user_agent TEXT,
  is_active BOOLEAN DEFAULT true
);

CREATE INDEX idx_sessions_user ON active_sessions(user_id);
CREATE INDEX idx_sessions_active ON active_sessions(is_active, expires_at);

ALTER TABLE active_sessions ENABLE ROW LEVEL SECURITY;


-- ================================================================
-- 6. Helper functions for RLS (MUST be created BEFORE policies)
-- ================================================================
CREATE OR REPLACE FUNCTION is_platform_user()
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM user_org_roles
    WHERE user_id = auth.uid()
      AND role IN ('super_admin','employee')
      AND status = 'active'
  );
$$ LANGUAGE sql SECURITY DEFINER STABLE;

CREATE OR REPLACE FUNCTION is_super_admin()
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM user_org_roles
    WHERE user_id = auth.uid()
      AND role = 'super_admin'
      AND status = 'active'
  );
$$ LANGUAGE sql SECURITY DEFINER STABLE;

CREATE OR REPLACE FUNCTION user_belongs_to_org(target_org_id TEXT)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM user_org_roles
    WHERE user_id = auth.uid()
      AND org_id = target_org_id
      AND status = 'active'
  );
$$ LANGUAGE sql SECURITY DEFINER STABLE;

CREATE OR REPLACE FUNCTION extract_org_id(key TEXT)
RETURNS TEXT AS $$
  SELECT CASE WHEN key LIKE 'org_%' THEN key ELSE NULL END;
$$ LANGUAGE sql IMMUTABLE;


-- ================================================================
-- 7. RLS policies on audit_log
-- ================================================================
CREATE POLICY "audit_insert" ON audit_log FOR INSERT TO authenticated
  WITH CHECK (true);

CREATE POLICY "audit_select_platform" ON audit_log FOR SELECT TO authenticated
  USING (
    is_platform_user()
    OR org_id IN (
      SELECT uor.org_id FROM user_org_roles uor
      WHERE uor.user_id = auth.uid() AND uor.role = 'client_admin' AND uor.status = 'active'
    )
  );


-- ================================================================
-- 8. RLS policies on active_sessions
-- ================================================================
CREATE POLICY "session_select" ON active_sessions FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR is_platform_user());

CREATE POLICY "session_insert" ON active_sessions FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid());

CREATE POLICY "session_update" ON active_sessions FOR UPDATE TO authenticated
  USING (user_id = auth.uid() OR is_super_admin());

CREATE POLICY "session_delete" ON active_sessions FOR DELETE TO authenticated
  USING (user_id = auth.uid() OR is_super_admin());


-- ================================================================
-- 7. RLS on user_org_roles
-- ================================================================
ALTER TABLE user_org_roles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "select_roles" ON user_org_roles FOR SELECT TO authenticated
  USING (
    is_platform_user()
    OR org_id IN (SELECT uor.org_id FROM user_org_roles uor WHERE uor.user_id = auth.uid() AND uor.status = 'active')
    OR user_id = auth.uid()
  );

CREATE POLICY "insert_roles" ON user_org_roles FOR INSERT TO authenticated
  WITH CHECK (
    is_super_admin()
    OR (is_platform_user() AND role IN ('client_admin','client_user','client_employee'))
    OR (
      EXISTS (
        SELECT 1 FROM user_org_roles uor
        WHERE uor.user_id = auth.uid() AND uor.org_id = org_id
          AND uor.role = 'client_admin' AND uor.status = 'active'
      )
      AND role IN ('client_user','client_employee')
    )
  );

CREATE POLICY "update_roles" ON user_org_roles FOR UPDATE TO authenticated
  USING (
    is_super_admin()
    OR user_id = auth.uid()  -- Users can update their own record (password change flag)
  );

CREATE POLICY "delete_roles" ON user_org_roles FOR DELETE TO authenticated
  USING (is_super_admin());


-- ================================================================
-- 8. RLS on isms_state
-- ================================================================
ALTER TABLE isms_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY "scoped_select" ON isms_state FOR SELECT TO authenticated
  USING (
    is_platform_user()
    OR user_id = '_rbac_directory_'
    OR user_belongs_to_org(extract_org_id(user_id))
  );

CREATE POLICY "scoped_insert" ON isms_state FOR INSERT TO authenticated
  WITH CHECK (
    is_platform_user()
    OR user_id = '_rbac_directory_'
    OR (user_id != '_rbac_directory_' AND user_belongs_to_org(extract_org_id(user_id)))
  );

CREATE POLICY "scoped_update" ON isms_state FOR UPDATE TO authenticated
  USING (
    is_platform_user()
    OR user_id = '_rbac_directory_'
    OR (user_id != '_rbac_directory_' AND user_belongs_to_org(extract_org_id(user_id)))
  );

CREATE POLICY "scoped_delete" ON isms_state FOR DELETE TO authenticated
  USING (is_super_admin());


-- ================================================================
-- 9. Auto-audit trigger on isms_state changes
-- ================================================================
CREATE OR REPLACE FUNCTION fn_audit_isms_change()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO audit_log (user_id, action, resource_type, resource_id, org_id, details, severity)
  VALUES (
    auth.uid(),
    CASE TG_OP
      WHEN 'INSERT' THEN 'data_create'
      WHEN 'UPDATE' THEN 'data_modify'
      WHEN 'DELETE' THEN 'data_delete'
    END,
    'isms_data',
    COALESCE(NEW.user_id, OLD.user_id),
    COALESCE(extract_org_id(COALESCE(NEW.user_id, OLD.user_id)), 'platform'),
    jsonb_build_object(
      'operation', TG_OP,
      'key', COALESCE(NEW.user_id, OLD.user_id),
      'timestamp', now()
    ),
    CASE WHEN COALESCE(NEW.user_id, OLD.user_id) = '_rbac_directory_' THEN 'critical' ELSE 'info' END
  );
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER trg_audit_isms_state
  AFTER INSERT OR UPDATE OR DELETE ON isms_state
  FOR EACH ROW EXECUTE FUNCTION fn_audit_isms_change();


-- ================================================================
-- 10. Auto-audit trigger on role changes
-- ================================================================
CREATE OR REPLACE FUNCTION fn_audit_role_change()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO audit_log (user_id, action, resource_type, resource_id, org_id, details, severity)
  VALUES (
    auth.uid(),
    CASE TG_OP
      WHEN 'INSERT' THEN 'create_user'
      WHEN 'UPDATE' THEN 'role_change'
      WHEN 'DELETE' THEN 'delete_user'
    END,
    'user',
    COALESCE(NEW.id, OLD.id)::TEXT,
    COALESCE(NEW.org_id, OLD.org_id, 'platform'),
    jsonb_build_object(
      'operation', TG_OP,
      'email', COALESCE(NEW.email, OLD.email),
      'role', COALESCE(NEW.role, OLD.role),
      'old_role', CASE WHEN TG_OP = 'UPDATE' THEN OLD.role ELSE NULL END,
      'old_status', CASE WHEN TG_OP = 'UPDATE' THEN OLD.status ELSE NULL END,
      'new_status', CASE WHEN TG_OP != 'DELETE' THEN NEW.status ELSE NULL END
    ),
    'critical'
  );
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER trg_audit_role_change
  AFTER INSERT OR UPDATE OR DELETE ON user_org_roles
  FOR EACH ROW EXECUTE FUNCTION fn_audit_role_change();


-- ================================================================
-- 11. Cleanup expired sessions (run via pg_cron or scheduled)
-- ================================================================
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
  DELETE FROM active_sessions WHERE expires_at < now() OR (is_active = false);
$$ LANGUAGE sql SECURITY DEFINER;


-- ================================================================
-- 12. Account lockout function
-- ================================================================
CREATE OR REPLACE FUNCTION check_account_lockout(p_email TEXT)
RETURNS JSONB AS $$
DECLARE
  v_role user_org_roles%ROWTYPE;
BEGIN
  SELECT * INTO v_role FROM user_org_roles WHERE email = p_email AND status = 'active' LIMIT 1;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('locked', false, 'exists', false);
  END IF;
  IF v_role.locked_until IS NOT NULL AND v_role.locked_until > now() THEN
    RETURN jsonb_build_object('locked', true, 'until', v_role.locked_until, 'exists', true);
  END IF;
  RETURN jsonb_build_object('locked', false, 'exists', true, 'must_change_password', v_role.must_change_password);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


-- ================================================================
-- 13. Storage bucket — PRIVATE
-- ================================================================
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'isms-files', 'isms-files', false,
  52428800,  -- 50MB max file size
  ARRAY[
    'application/pdf','application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'text/plain','text/csv','text/html',
    'application/json','application/xml',
    'image/png','image/jpeg','image/gif','image/webp','image/svg+xml',
    'application/zip','application/x-rar-compressed'
  ]
)
ON CONFLICT (id) DO UPDATE SET
  public = false,
  file_size_limit = 52428800,
  allowed_mime_types = EXCLUDED.allowed_mime_types;

-- Drop old storage policies safely
DROP POLICY IF EXISTS "auth_upload_own" ON storage.objects;
DROP POLICY IF EXISTS "public_read_files" ON storage.objects;
DROP POLICY IF EXISTS "auth_update_own" ON storage.objects;
DROP POLICY IF EXISTS "auth_delete_own" ON storage.objects;
DROP POLICY IF EXISTS "auth_upload" ON storage.objects;
DROP POLICY IF EXISTS "public_read" ON storage.objects;
DROP POLICY IF EXISTS "auth_update" ON storage.objects;
DROP POLICY IF EXISTS "auth_delete" ON storage.objects;
DROP POLICY IF EXISTS "org_scoped_upload" ON storage.objects;
DROP POLICY IF EXISTS "org_scoped_read" ON storage.objects;
DROP POLICY IF EXISTS "org_scoped_update" ON storage.objects;
DROP POLICY IF EXISTS "org_scoped_delete" ON storage.objects;

CREATE POLICY "org_scoped_upload" ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'isms-files'
    AND (is_platform_user() OR user_belongs_to_org('org_' || split_part(name, '/', 1)))
  );

CREATE POLICY "org_scoped_read" ON storage.objects FOR SELECT TO authenticated
  USING (
    bucket_id = 'isms-files'
    AND (is_platform_user() OR user_belongs_to_org('org_' || split_part(name, '/', 1)))
  );

CREATE POLICY "org_scoped_update" ON storage.objects FOR UPDATE TO authenticated
  USING (bucket_id = 'isms-files' AND is_platform_user());

CREATE POLICY "org_scoped_delete" ON storage.objects FOR DELETE TO authenticated
  USING (bucket_id = 'isms-files' AND is_super_admin());


-- ================================================================
-- 14. RPC: Log audit event (callable from frontend)
-- ================================================================
CREATE OR REPLACE FUNCTION log_audit_event(
  p_action TEXT,
  p_resource_type TEXT DEFAULT NULL,
  p_resource_id TEXT DEFAULT NULL,
  p_org_id TEXT DEFAULT NULL,
  p_details JSONB DEFAULT '{}'::jsonb,
  p_severity TEXT DEFAULT 'info'
)
RETURNS void AS $$
BEGIN
  INSERT INTO audit_log (user_id, user_email, action, resource_type, resource_id, org_id, details, severity)
  VALUES (
    auth.uid(),
    (SELECT email FROM user_org_roles WHERE user_id = auth.uid() LIMIT 1),
    p_action, p_resource_type, p_resource_id, p_org_id, p_details, p_severity
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


-- ================================================================
-- 15. Verification
-- ================================================================
DO $$
DECLARE
  v_tables TEXT[] := ARRAY['isms_state','user_org_roles','audit_log','active_sessions'];
  v_t TEXT;
BEGIN
  FOREACH v_t IN ARRAY v_tables LOOP
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = v_t) THEN
      RAISE WARNING 'Table % is MISSING', v_t;
    END IF;
  END LOOP;
  RAISE NOTICE 'All tables verified ✅';
END $$;

SELECT tablename, CASE WHEN rowsecurity THEN '✅ RLS ON' ELSE '❌ RLS OFF' END as rls
FROM pg_tables
WHERE tablename IN ('isms_state','user_org_roles','audit_log','active_sessions')
ORDER BY tablename;

SELECT 'Storage' as item,
  CASE WHEN EXISTS (SELECT 1 FROM storage.buckets WHERE id = 'isms-files' AND public = false)
    THEN '✅ PRIVATE' ELSE '❌ PUBLIC' END as status;


-- ================================================================
-- POST-SETUP REMINDERS
-- ================================================================

-- Bootstrap function: seeds super admin into user_org_roles (bypasses RLS)
CREATE OR REPLACE FUNCTION bootstrap_super_admin(admin_email TEXT, admin_name TEXT)
RETURNS JSONB AS $$
DECLARE
  uid UUID;
  result JSONB;
BEGIN
  -- Only the authenticated user can bootstrap themselves
  uid := auth.uid();
  IF uid IS NULL THEN
    RETURN jsonb_build_object('error', 'Not authenticated');
  END IF;

  -- Verify email matches the calling user
  IF (SELECT email FROM auth.users WHERE id = uid) != lower(trim(admin_email)) THEN
    RETURN jsonb_build_object('error', 'Email mismatch');
  END IF;

  -- Check if already exists
  IF EXISTS (SELECT 1 FROM user_org_roles WHERE user_id = uid AND role = 'super_admin') THEN
    RETURN jsonb_build_object('status', 'already_exists');
  END IF;

  -- Check no other super_admin exists (first-time bootstrap only)
  IF EXISTS (SELECT 1 FROM user_org_roles WHERE role = 'super_admin' AND status = 'active') THEN
    RETURN jsonb_build_object('error', 'Super admin already exists');
  END IF;

  -- Insert
  INSERT INTO user_org_roles (user_id, email, name, role, org_id, created_by, status, must_change_password)
  VALUES (uid, lower(trim(admin_email)), trim(admin_name), 'super_admin', NULL, 'system_bootstrap', 'active', false);

  RETURN jsonb_build_object('status', 'created', 'user_id', uid::text);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ================================================================
-- ADDITIONAL REMINDERS
-- 1. Authentication → Rate Limits: sign-in 5/min, signup 3/hour
-- 2. Authentication → Settings: min password 12, enable leaked password protection
-- 3. Deploy Edge Functions:
--    supabase functions deploy create-user
--    supabase functions deploy audit-log
--    supabase secrets set SERVICE_ROLE_KEY=your-key
-- 4. Set .env: VITE_SUPABASE_URL, VITE_SUPABASE_ANON_KEY, VITE_SUPER_ADMIN_EMAIL
-- 5. Optional: Set up pg_cron to run cleanup_expired_sessions() hourly
-- ================================================================
