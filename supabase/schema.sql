-- Create contacts table for Fynsor website contact form
-- Simple schema matching the basic contact form fields

-- Drop table if it exists with wrong schema
DROP TABLE IF EXISTS contacts;

-- Create contacts table with correct column names
CREATE TABLE contacts (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  company TEXT,
  message TEXT,
  ip_address TEXT,
  user_agent TEXT,
  referrer TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create index on created_at for efficient querying
CREATE INDEX idx_contacts_created_at ON contacts(created_at DESC);

-- Create index on email for potential duplicate checking
CREATE INDEX idx_contacts_email ON contacts(email);

-- Enable Row Level Security (RLS)
ALTER TABLE contacts ENABLE ROW LEVEL SECURITY;

-- Create policy to allow service role to insert and read
CREATE POLICY "Service role can manage contacts" ON contacts
  FOR ALL USING (auth.role() = 'service_role');

-- Add comment to table
COMMENT ON TABLE contacts IS 'Contact form submissions from the Fynsor website';