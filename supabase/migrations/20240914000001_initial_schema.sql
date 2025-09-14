-- Initial schema for Fynsor Consulting CRE platform
-- Includes encryption for PII data and audit logging

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create custom encryption functions for PII data
-- These functions use AES-256 encryption with a key derived from environment
CREATE OR REPLACE FUNCTION encrypt_pii(data TEXT, key_name TEXT DEFAULT 'default')
RETURNS TEXT AS $$
BEGIN
    -- In production, the encryption key should be stored securely
    -- This is a simplified version - in real implementation use Supabase Vault
    RETURN encode(
        encrypt(
            data::bytea,
            digest(current_setting('app.encryption_key', true) || key_name, 'sha256'),
            'aes'
        ),
        'base64'
    );
EXCEPTION
    WHEN OTHERS THEN
        -- Log the error but don't expose sensitive information
        RAISE LOG 'Encryption failed for key: %', key_name;
        RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION decrypt_pii(encrypted_data TEXT, key_name TEXT DEFAULT 'default')
RETURNS TEXT AS $$
BEGIN
    IF encrypted_data IS NULL OR encrypted_data = '' THEN
        RETURN NULL;
    END IF;

    RETURN convert_from(
        decrypt(
            decode(encrypted_data, 'base64'),
            digest(current_setting('app.encryption_key', true) || key_name, 'sha256'),
            'aes'
        ),
        'UTF8'
    );
EXCEPTION
    WHEN OTHERS THEN
        -- Log the error but don't expose sensitive information
        RAISE LOG 'Decryption failed for key: %', key_name;
        RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Contacts table with encrypted PII fields
CREATE TABLE contacts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Encrypted PII fields
    name_encrypted TEXT,
    email_encrypted TEXT,
    company_encrypted TEXT,
    phone_encrypted TEXT,
    message_encrypted TEXT,

    -- Non-PII fields (can be stored in plaintext)
    property_type TEXT CHECK (property_type IN (
        'office', 'retail', 'industrial', 'multifamily',
        'hospitality', 'mixed_use', 'land', 'other'
    )),
    investment_size TEXT CHECK (investment_size IN (
        'under_1m', '1m_5m', '5m_10m', '10m_25m',
        '25m_50m', '50m_100m', 'over_100m'
    )),

    -- Technical fields
    ip_address INET,
    user_agent TEXT,
    referrer TEXT,
    utm_source TEXT,
    utm_medium TEXT,
    utm_campaign TEXT,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    status TEXT DEFAULT 'new' CHECK (status IN ('new', 'contacted', 'qualified', 'closed', 'archived')),

    -- Indexes for performance (on non-encrypted fields only)
    CONSTRAINT contacts_created_at_idx CHECK (created_at IS NOT NULL)
);

-- Create indexes for non-encrypted searchable fields
CREATE INDEX idx_contacts_property_type ON contacts(property_type);
CREATE INDEX idx_contacts_investment_size ON contacts(investment_size);
CREATE INDEX idx_contacts_created_at ON contacts(created_at DESC);
CREATE INDEX idx_contacts_status ON contacts(status);
CREATE INDEX idx_contacts_ip_address ON contacts(ip_address);

-- Audit log table for tracking all data access and modifications
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Action details
    action TEXT NOT NULL CHECK (action IN (
        'contact_created', 'contact_viewed', 'contact_updated', 'contact_deleted',
        'data_exported', 'user_login', 'user_logout', 'admin_action',
        'encryption_operation', 'failed_login', 'rate_limit_exceeded'
    )),

    -- User context (if available)
    user_id UUID,
    user_email TEXT,
    user_role TEXT,

    -- Technical context
    ip_address INET,
    user_agent TEXT,
    request_id TEXT,
    session_id TEXT,

    -- Resource details
    resource_type TEXT,
    resource_id UUID,

    -- Additional metadata (non-PII only)
    metadata JSONB DEFAULT '{}',

    -- Security fields
    risk_score INTEGER DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    flagged BOOLEAN DEFAULT FALSE,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Constraints
    CONSTRAINT audit_log_action_not_empty CHECK (action != ''),
    CONSTRAINT audit_log_created_at_not_null CHECK (created_at IS NOT NULL)
);

-- Create indexes for audit log queries
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at DESC);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_ip_address ON audit_log(ip_address);
CREATE INDEX idx_audit_log_flagged ON audit_log(flagged) WHERE flagged = TRUE;
CREATE INDEX idx_audit_log_risk_score ON audit_log(risk_score) WHERE risk_score > 50;

-- Rate limiting table for API endpoint protection
CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identifier TEXT NOT NULL, -- IP address or user ID
    endpoint TEXT NOT NULL,
    requests_count INTEGER DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    blocked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create unique index for rate limiting lookups
CREATE UNIQUE INDEX idx_rate_limits_identifier_endpoint ON rate_limits(identifier, endpoint);
CREATE INDEX idx_rate_limits_window_start ON rate_limits(window_start);
CREATE INDEX idx_rate_limits_blocked_until ON rate_limits(blocked_until);

-- Users table for admin authentication (if needed)
CREATE TABLE admin_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin' CHECK (role IN ('admin', 'super_admin', 'readonly')),
    active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for admin users
CREATE UNIQUE INDEX idx_admin_users_email ON admin_users(email);
CREATE INDEX idx_admin_users_active ON admin_users(active) WHERE active = TRUE;

-- Create trigger function for updating updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for updated_at
CREATE TRIGGER update_contacts_updated_at
    BEFORE UPDATE ON contacts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_rate_limits_updated_at
    BEFORE UPDATE ON rate_limits
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_admin_users_updated_at
    BEFORE UPDATE ON admin_users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to log audit events
CREATE OR REPLACE FUNCTION log_audit_event(
    p_action TEXT,
    p_user_id UUID DEFAULT NULL,
    p_user_email TEXT DEFAULT NULL,
    p_user_role TEXT DEFAULT NULL,
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL,
    p_request_id TEXT DEFAULT NULL,
    p_session_id TEXT DEFAULT NULL,
    p_resource_type TEXT DEFAULT NULL,
    p_resource_id UUID DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}',
    p_risk_score INTEGER DEFAULT 0
)
RETURNS UUID AS $$
DECLARE
    audit_id UUID;
BEGIN
    INSERT INTO audit_log (
        action, user_id, user_email, user_role, ip_address, user_agent,
        request_id, session_id, resource_type, resource_id, metadata, risk_score
    )
    VALUES (
        p_action, p_user_id, p_user_email, p_user_role, p_ip_address, p_user_agent,
        p_request_id, p_session_id, p_resource_type, p_resource_id, p_metadata, p_risk_score
    )
    RETURNING id INTO audit_id;

    RETURN audit_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to check and update rate limits
CREATE OR REPLACE FUNCTION check_rate_limit(
    p_identifier TEXT,
    p_endpoint TEXT,
    p_limit INTEGER DEFAULT 100,
    p_window_minutes INTEGER DEFAULT 60
)
RETURNS BOOLEAN AS $$
DECLARE
    current_count INTEGER;
    window_start TIMESTAMP WITH TIME ZONE;
    is_blocked BOOLEAN DEFAULT FALSE;
BEGIN
    -- Check if currently blocked
    SELECT blocked_until > NOW() INTO is_blocked
    FROM rate_limits
    WHERE identifier = p_identifier AND endpoint = p_endpoint;

    IF is_blocked THEN
        RETURN FALSE;
    END IF;

    -- Get or create rate limit record
    window_start := NOW() - INTERVAL '1 minute' * p_window_minutes;

    INSERT INTO rate_limits (identifier, endpoint, requests_count, window_start)
    VALUES (p_identifier, p_endpoint, 1, NOW())
    ON CONFLICT (identifier, endpoint)
    DO UPDATE SET
        requests_count = CASE
            WHEN rate_limits.window_start < window_start THEN 1
            ELSE rate_limits.requests_count + 1
        END,
        window_start = CASE
            WHEN rate_limits.window_start < window_start THEN NOW()
            ELSE rate_limits.window_start
        END,
        blocked_until = CASE
            WHEN (rate_limits.window_start >= window_start AND rate_limits.requests_count >= p_limit)
            THEN NOW() + INTERVAL '1 hour'
            ELSE NULL
        END,
        updated_at = NOW()
    RETURNING requests_count INTO current_count;

    RETURN current_count <= p_limit;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Row Level Security (RLS) policies
ALTER TABLE contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;

-- RLS policies for contacts (admin only access)
CREATE POLICY "Contacts are viewable by authenticated admin users only"
    ON contacts FOR SELECT
    USING (auth.role() = 'authenticated' AND auth.jwt() ->> 'role' = 'admin');

CREATE POLICY "Contacts are insertable by anyone (for contact form)"
    ON contacts FOR INSERT
    WITH CHECK (true);

-- RLS policies for audit_log (admin only access)
CREATE POLICY "Audit logs are viewable by authenticated admin users only"
    ON audit_log FOR SELECT
    USING (auth.role() = 'authenticated' AND auth.jwt() ->> 'role' = 'admin');

CREATE POLICY "Audit logs are insertable by system"
    ON audit_log FOR INSERT
    WITH CHECK (true);

-- RLS policies for admin_users (self-access only)
CREATE POLICY "Admin users can view their own record"
    ON admin_users FOR SELECT
    USING (auth.uid() = id);

-- Grant necessary permissions
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT ON contacts TO anon, authenticated;
GRANT SELECT ON audit_log TO authenticated;
GRANT INSERT ON audit_log TO anon, authenticated;
GRANT SELECT, UPDATE ON rate_limits TO anon, authenticated;
GRANT INSERT ON rate_limits TO anon, authenticated;

-- Create initial admin user (password should be changed immediately)
-- Password hash for 'tempPassword123!' - MUST BE CHANGED IN PRODUCTION
INSERT INTO admin_users (email, password_hash, role)
VALUES (
    'admin@fynsor.com',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/hXjbHKo8y',
    'super_admin'
);

-- Add helpful comments
COMMENT ON TABLE contacts IS 'Contact form submissions with encrypted PII data';
COMMENT ON TABLE audit_log IS 'Comprehensive audit trail for all system actions';
COMMENT ON TABLE rate_limits IS 'Rate limiting for API endpoints';
COMMENT ON TABLE admin_users IS 'Administrative users for backend access';

COMMENT ON FUNCTION encrypt_pii(TEXT, TEXT) IS 'Encrypts PII data using AES-256';
COMMENT ON FUNCTION decrypt_pii(TEXT, TEXT) IS 'Decrypts PII data using AES-256';
COMMENT ON FUNCTION log_audit_event IS 'Creates audit log entries for system actions';
COMMENT ON FUNCTION check_rate_limit IS 'Implements rate limiting for API endpoints';