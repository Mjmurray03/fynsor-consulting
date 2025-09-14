-- ==============================================
-- FYNSOR CONSULTING DATABASE SETUP
-- Run this script in Supabase SQL Editor
-- ==============================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ==============================================
-- CONTACTS TABLE WITH ENCRYPTION
-- ==============================================

CREATE TABLE contacts (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

  -- PII fields (will be encrypted at application level)
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  company TEXT,
  phone TEXT,
  message TEXT,

  -- Business data (not encrypted)
  property_type TEXT CHECK (property_type IN (
    'office', 'retail', 'industrial', 'multifamily',
    'hospitality', 'healthcare', 'mixed-use', 'other'
  )),
  investment_size TEXT CHECK (investment_size IN (
    'under-1m', '1m-5m', '5m-10m', '10m-25m',
    '25m-50m', '50m-100m', 'over-100m'
  )),

  -- Security metadata
  ip_address INET,
  user_agent TEXT,
  fingerprint TEXT,
  referrer TEXT,
  country TEXT,
  region TEXT,

  -- Status tracking
  status TEXT DEFAULT 'new' CHECK (status IN ('new', 'contacted', 'qualified', 'closed')),
  priority TEXT DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),

  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  contacted_at TIMESTAMP WITH TIME ZONE,

  -- Compliance
  gdpr_consent BOOLEAN DEFAULT FALSE,
  marketing_consent BOOLEAN DEFAULT FALSE,
  data_retention_until TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + INTERVAL '7 years')
);

-- ==============================================
-- AUDIT LOG TABLE
-- ==============================================

CREATE TABLE audit_log (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

  -- Action details
  action TEXT NOT NULL CHECK (action IN (
    'INSERT', 'UPDATE', 'DELETE', 'SELECT', 'LOGIN', 'LOGOUT', 'EXPORT'
  )),
  table_name TEXT,
  record_id UUID,

  -- Change tracking
  old_values JSONB,
  new_values JSONB,
  changed_fields TEXT[],

  -- User context
  user_id UUID,
  user_email TEXT,
  user_role TEXT,

  -- Security context
  ip_address INET,
  user_agent TEXT,
  session_id TEXT,

  -- Request metadata
  endpoint TEXT,
  method TEXT,
  metadata JSONB,

  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ==============================================
-- RATE LIMITING TABLE
-- ==============================================

CREATE TABLE rate_limits (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

  -- Rate limit key (IP, user, endpoint combination)
  rate_key TEXT NOT NULL,

  -- Rate limit data
  request_count INTEGER DEFAULT 1,
  window_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  window_duration INTERVAL DEFAULT '1 hour',

  -- Metadata
  ip_address INET,
  endpoint TEXT,
  user_id UUID,

  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

  UNIQUE(rate_key, window_start)
);

-- ==============================================
-- ADMIN USERS TABLE
-- ==============================================

CREATE TABLE admin_users (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

  -- Authentication
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,

  -- Profile
  full_name TEXT NOT NULL,
  role TEXT DEFAULT 'admin' CHECK (role IN ('admin', 'super_admin')),

  -- Security
  mfa_enabled BOOLEAN DEFAULT FALSE,
  mfa_secret TEXT,
  backup_codes TEXT[],

  -- Session management
  last_login TIMESTAMP WITH TIME ZONE,
  login_count INTEGER DEFAULT 0,
  failed_login_attempts INTEGER DEFAULT 0,
  account_locked_until TIMESTAMP WITH TIME ZONE,

  -- Status
  is_active BOOLEAN DEFAULT TRUE,
  email_verified BOOLEAN DEFAULT FALSE,

  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ==============================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================

-- Enable RLS on all tables
ALTER TABLE contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;

-- Contacts policies
CREATE POLICY "Anyone can insert contacts" ON contacts
  FOR INSERT WITH CHECK (true);

CREATE POLICY "Authenticated can read contacts" ON contacts
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Authenticated can update contacts" ON contacts
  FOR UPDATE USING (auth.role() = 'authenticated');

-- Audit log policies (read-only for security)
CREATE POLICY "Authenticated can read audit logs" ON audit_log
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "System can insert audit logs" ON audit_log
  FOR INSERT WITH CHECK (true);

-- Rate limits policies
CREATE POLICY "System can manage rate limits" ON rate_limits
  FOR ALL USING (true);

-- Admin users policies
CREATE POLICY "Admins can read admin users" ON admin_users
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Super admins can manage admin users" ON admin_users
  FOR ALL USING (auth.jwt() ->> 'role' = 'super_admin');

-- ==============================================
-- AUDIT TRIGGERS
-- ==============================================

-- Audit function for tracking all changes
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
DECLARE
  old_values JSONB := '{}';
  new_values JSONB := '{}';
  changed_fields TEXT[] := '{}';
  field_name TEXT;
BEGIN
  -- Handle different trigger operations
  IF TG_OP = 'DELETE' THEN
    old_values := row_to_json(OLD)::jsonb;
    INSERT INTO audit_log (
      action, table_name, record_id, old_values,
      ip_address, user_agent, session_id
    ) VALUES (
      TG_OP, TG_TABLE_NAME, OLD.id, old_values,
      inet_client_addr(),
      current_setting('application_name', true),
      current_setting('app.session_id', true)
    );
    RETURN OLD;

  ELSIF TG_OP = 'INSERT' THEN
    new_values := row_to_json(NEW)::jsonb;
    INSERT INTO audit_log (
      action, table_name, record_id, new_values,
      ip_address, user_agent, session_id
    ) VALUES (
      TG_OP, TG_TABLE_NAME, NEW.id, new_values,
      inet_client_addr(),
      current_setting('application_name', true),
      current_setting('app.session_id', true)
    );
    RETURN NEW;

  ELSIF TG_OP = 'UPDATE' THEN
    old_values := row_to_json(OLD)::jsonb;
    new_values := row_to_json(NEW)::jsonb;

    -- Detect changed fields
    FOR field_name IN SELECT jsonb_object_keys(new_values) LOOP
      IF old_values ->> field_name IS DISTINCT FROM new_values ->> field_name THEN
        changed_fields := array_append(changed_fields, field_name);
      END IF;
    END LOOP;

    INSERT INTO audit_log (
      action, table_name, record_id, old_values, new_values, changed_fields,
      ip_address, user_agent, session_id
    ) VALUES (
      TG_OP, TG_TABLE_NAME, NEW.id, old_values, new_values, changed_fields,
      inet_client_addr(),
      current_setting('application_name', true),
      current_setting('app.session_id', true)
    );
    RETURN NEW;
  END IF;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Apply audit triggers
CREATE TRIGGER contacts_audit_trigger
  AFTER INSERT OR UPDATE OR DELETE ON contacts
  FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

CREATE TRIGGER admin_users_audit_trigger
  AFTER INSERT OR UPDATE OR DELETE ON admin_users
  FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

-- ==============================================
-- AUTOMATIC TIMESTAMP UPDATES
-- ==============================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply timestamp triggers
CREATE TRIGGER update_contacts_updated_at
  BEFORE UPDATE ON contacts
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_admin_users_updated_at
  BEFORE UPDATE ON admin_users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_rate_limits_updated_at
  BEFORE UPDATE ON rate_limits
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ==============================================
-- DATA RETENTION AND CLEANUP
-- ==============================================

-- Function to clean up old audit logs (keep 2 years)
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM audit_log
  WHERE created_at < NOW() - INTERVAL '2 years';

  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired rate limits
CREATE OR REPLACE FUNCTION cleanup_expired_rate_limits()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM rate_limits
  WHERE (window_start + window_duration) < NOW() - INTERVAL '1 day';

  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to handle GDPR data retention
CREATE OR REPLACE FUNCTION cleanup_expired_contacts()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  -- Delete contacts past their retention period
  DELETE FROM contacts
  WHERE data_retention_until < NOW();

  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ==============================================
-- SECURITY FUNCTIONS
-- ==============================================

-- Function to check rate limits
CREATE OR REPLACE FUNCTION check_rate_limit(
  p_rate_key TEXT,
  p_limit INTEGER DEFAULT 5,
  p_window INTERVAL DEFAULT '1 hour'
)
RETURNS BOOLEAN AS $$
DECLARE
  current_count INTEGER;
  window_start_time TIMESTAMP WITH TIME ZONE;
BEGIN
  window_start_time := date_trunc('hour', NOW());

  -- Get current count for this window
  SELECT COALESCE(request_count, 0) INTO current_count
  FROM rate_limits
  WHERE rate_key = p_rate_key
    AND window_start = window_start_time;

  -- If no record exists or count is under limit
  IF current_count IS NULL OR current_count < p_limit THEN
    -- Upsert rate limit record
    INSERT INTO rate_limits (rate_key, request_count, window_start, window_duration)
    VALUES (p_rate_key, 1, window_start_time, p_window)
    ON CONFLICT (rate_key, window_start)
    DO UPDATE SET
      request_count = rate_limits.request_count + 1,
      updated_at = NOW();

    RETURN TRUE;
  ELSE
    RETURN FALSE;
  END IF;
END;
$$ LANGUAGE plpgsql;

-- ==============================================
-- INDEXES FOR PERFORMANCE
-- ==============================================

-- Contacts indexes
CREATE INDEX idx_contacts_email ON contacts(email);
CREATE INDEX idx_contacts_created_at ON contacts(created_at);
CREATE INDEX idx_contacts_status ON contacts(status);
CREATE INDEX idx_contacts_ip_address ON contacts(ip_address);
CREATE INDEX idx_contacts_property_type ON contacts(property_type);
CREATE INDEX idx_contacts_investment_size ON contacts(investment_size);

-- Audit log indexes
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX idx_audit_log_table_name ON audit_log(table_name);
CREATE INDEX idx_audit_log_record_id ON audit_log(record_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_ip_address ON audit_log(ip_address);

-- Rate limits indexes
CREATE INDEX idx_rate_limits_rate_key ON rate_limits(rate_key);
CREATE INDEX idx_rate_limits_window_start ON rate_limits(window_start);
CREATE INDEX idx_rate_limits_ip_address ON rate_limits(ip_address);

-- Admin users indexes
CREATE UNIQUE INDEX idx_admin_users_email ON admin_users(email);
CREATE INDEX idx_admin_users_role ON admin_users(role);
CREATE INDEX idx_admin_users_last_login ON admin_users(last_login);

-- ==============================================
-- INITIAL DATA SETUP
-- ==============================================

-- Insert default super admin (password should be changed immediately)
-- Default password: "TempPassword123!" (hash this properly in production)
INSERT INTO admin_users (
  email,
  password_hash,
  salt,
  full_name,
  role,
  is_active,
  email_verified
) VALUES (
  'admin@fynsor.com',
  crypt('TempPassword123!', gen_salt('bf', 12)),
  gen_salt('bf', 12),
  'Fynsor Administrator',
  'super_admin',
  true,
  true
) ON CONFLICT (email) DO NOTHING;

-- ==============================================
-- VERIFICATION QUERIES
-- ==============================================

-- Verify table creation
SELECT table_name, table_type
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN ('contacts', 'audit_log', 'rate_limits', 'admin_users');

-- Verify RLS is enabled
SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename IN ('contacts', 'audit_log', 'rate_limits', 'admin_users');

-- Verify policies exist
SELECT policyname, tablename, cmd, qual
FROM pg_policies
WHERE schemaname = 'public';

-- Verify triggers exist
SELECT trigger_name, event_object_table, action_timing, event_manipulation
FROM information_schema.triggers
WHERE trigger_schema = 'public';

-- ==============================================
-- COMPLETION MESSAGE
-- ==============================================

DO $$
BEGIN
  RAISE NOTICE 'Fynsor Consulting database setup completed successfully!';
  RAISE NOTICE 'Tables created: contacts, audit_log, rate_limits, admin_users';
  RAISE NOTICE 'Row Level Security enabled on all tables';
  RAISE NOTICE 'Audit triggers configured for compliance tracking';
  RAISE NOTICE 'Rate limiting functions ready';
  RAISE NOTICE 'Default admin user created: admin@fynsor.com';
  RAISE NOTICE 'IMPORTANT: Change the default admin password immediately!';
END $$;