export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export interface Database {
  public: {
    Tables: {
      contacts: {
        Row: {
          id: string
          name_encrypted: string | null
          email_encrypted: string | null
          company_encrypted: string | null
          phone_encrypted: string | null
          message_encrypted: string | null
          property_type: PropertyType | null
          investment_size: InvestmentSize | null
          ip_address: string | null
          user_agent: string | null
          referrer: string | null
          utm_source: string | null
          utm_medium: string | null
          utm_campaign: string | null
          created_at: string
          updated_at: string
          status: ContactStatus
        }
        Insert: {
          id?: string
          name_encrypted?: string | null
          email_encrypted?: string | null
          company_encrypted?: string | null
          phone_encrypted?: string | null
          message_encrypted?: string | null
          property_type?: PropertyType | null
          investment_size?: InvestmentSize | null
          ip_address?: string | null
          user_agent?: string | null
          referrer?: string | null
          utm_source?: string | null
          utm_medium?: string | null
          utm_campaign?: string | null
          created_at?: string
          updated_at?: string
          status?: ContactStatus
        }
        Update: {
          id?: string
          name_encrypted?: string | null
          email_encrypted?: string | null
          company_encrypted?: string | null
          phone_encrypted?: string | null
          message_encrypted?: string | null
          property_type?: PropertyType | null
          investment_size?: InvestmentSize | null
          ip_address?: string | null
          user_agent?: string | null
          referrer?: string | null
          utm_source?: string | null
          utm_medium?: string | null
          utm_campaign?: string | null
          created_at?: string
          updated_at?: string
          status?: ContactStatus
        }
        Relationships: []
      }
      audit_log: {
        Row: {
          id: string
          action: AuditAction
          user_id: string | null
          user_email: string | null
          user_role: string | null
          ip_address: string | null
          user_agent: string | null
          request_id: string | null
          session_id: string | null
          resource_type: string | null
          resource_id: string | null
          metadata: Json
          risk_score: number
          flagged: boolean
          created_at: string
        }
        Insert: {
          id?: string
          action: AuditAction
          user_id?: string | null
          user_email?: string | null
          user_role?: string | null
          ip_address?: string | null
          user_agent?: string | null
          request_id?: string | null
          session_id?: string | null
          resource_type?: string | null
          resource_id?: string | null
          metadata?: Json
          risk_score?: number
          flagged?: boolean
          created_at?: string
        }
        Update: {
          id?: string
          action?: AuditAction
          user_id?: string | null
          user_email?: string | null
          user_role?: string | null
          ip_address?: string | null
          user_agent?: string | null
          request_id?: string | null
          session_id?: string | null
          resource_type?: string | null
          resource_id?: string | null
          metadata?: Json
          risk_score?: number
          flagged?: boolean
          created_at?: string
        }
        Relationships: []
      }
      rate_limits: {
        Row: {
          id: string
          identifier: string
          endpoint: string
          requests_count: number
          window_start: string
          blocked_until: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          identifier: string
          endpoint: string
          requests_count?: number
          window_start?: string
          blocked_until?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          identifier?: string
          endpoint?: string
          requests_count?: number
          window_start?: string
          blocked_until?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: []
      }
      admin_users: {
        Row: {
          id: string
          email: string
          password_hash: string
          role: AdminRole
          active: boolean
          last_login: string | null
          failed_login_attempts: number
          locked_until: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          email: string
          password_hash: string
          role?: AdminRole
          active?: boolean
          last_login?: string | null
          failed_login_attempts?: number
          locked_until?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          email?: string
          password_hash?: string
          role?: AdminRole
          active?: boolean
          last_login?: string | null
          failed_login_attempts?: number
          locked_until?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      encrypt_pii: {
        Args: {
          data: string
          key_name?: string
        }
        Returns: string
      }
      decrypt_pii: {
        Args: {
          encrypted_data: string
          key_name?: string
        }
        Returns: string
      }
      log_audit_event: {
        Args: {
          p_action: string
          p_user_id?: string
          p_user_email?: string
          p_user_role?: string
          p_ip_address?: string
          p_user_agent?: string
          p_request_id?: string
          p_session_id?: string
          p_resource_type?: string
          p_resource_id?: string
          p_metadata?: Json
          p_risk_score?: number
        }
        Returns: string
      }
      check_rate_limit: {
        Args: {
          p_identifier: string
          p_endpoint: string
          p_limit?: number
          p_window_minutes?: number
        }
        Returns: boolean
      }
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

// Enum types for better type safety
export type PropertyType =
  | 'office'
  | 'retail'
  | 'industrial'
  | 'multifamily'
  | 'hospitality'
  | 'mixed_use'
  | 'land'
  | 'other'

export type InvestmentSize =
  | 'under_1m'
  | '1m_5m'
  | '5m_10m'
  | '10m_25m'
  | '25m_50m'
  | '50m_100m'
  | 'over_100m'

export type ContactStatus =
  | 'new'
  | 'contacted'
  | 'qualified'
  | 'closed'
  | 'archived'

export type AuditAction =
  | 'contact_created'
  | 'contact_viewed'
  | 'contact_updated'
  | 'contact_deleted'
  | 'data_exported'
  | 'user_login'
  | 'user_logout'
  | 'admin_action'
  | 'encryption_operation'
  | 'failed_login'
  | 'rate_limit_exceeded'

export type AdminRole =
  | 'admin'
  | 'super_admin'
  | 'readonly'

// Decrypted contact type for frontend usage
export interface DecryptedContact {
  id: string
  name: string
  email: string
  company?: string
  phone?: string
  message?: string
  propertyType?: PropertyType
  investmentSize?: InvestmentSize
  ipAddress?: string
  userAgent?: string
  referrer?: string
  utmSource?: string
  utmMedium?: string
  utmCampaign?: string
  createdAt: string
  updatedAt: string
  status: ContactStatus
}

// Contact form input types
export interface ContactFormData {
  name: string
  email: string
  company?: string
  phone?: string
  message?: string
  propertyType?: PropertyType
  investmentSize?: InvestmentSize
}

// API response types
export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  error?: string
  message?: string
}

export interface ContactCreateResponse {
  success: boolean
  contactId?: string
  error?: string
}

export interface ContactListResponse {
  success: boolean
  contacts?: DecryptedContact[]
  total?: number
  error?: string
}

// Audit log entry type
export interface AuditLogEntry {
  id: string
  action: AuditAction
  userId?: string
  userEmail?: string
  userRole?: string
  ipAddress?: string
  userAgent?: string
  requestId?: string
  sessionId?: string
  resourceType?: string
  resourceId?: string
  metadata: Record<string, any>
  riskScore: number
  flagged: boolean
  createdAt: string
}

// Rate limiting types
export interface RateLimitInfo {
  id: string
  identifier: string
  endpoint: string
  requestsCount: number
  windowStart: string
  blockedUntil?: string
  createdAt: string
  updatedAt: string
}

// Admin user types
export interface AdminUser {
  id: string
  email: string
  role: AdminRole
  active: boolean
  lastLogin?: string
  failedLoginAttempts: number
  lockedUntil?: string
  createdAt: string
  updatedAt: string
}

// Authentication types
export interface LoginCredentials {
  email: string
  password: string
}

export interface AuthSession {
  user: AdminUser
  token: string
  expiresAt: string
}

// CRE Financial Modeling Types
export interface PropertyAnalysis {
  id: string
  propertyType: PropertyType
  location: {
    address: string
    city: string
    state: string
    zipCode: string
    market: string
  }
  financials: {
    purchasePrice: number
    downPayment: number
    loanAmount: number
    interestRate: number
    loanTerm: number
    closingCosts: number
    renovationCosts?: number
  }
  income: {
    grossRent: number
    otherIncome?: number
    vacancy?: number
    effectiveGrossIncome: number
  }
  expenses: {
    propertyTaxes: number
    insurance: number
    maintenance: number
    management?: number
    utilities?: number
    other?: number
    totalExpenses: number
  }
  metrics: {
    noi: number // Net Operating Income
    capRate: number
    cashOnCash: number
    dscr: number // Debt Service Coverage Ratio
    ltv: number // Loan to Value
    irr?: number // Internal Rate of Return
    npv?: number // Net Present Value
  }
  createdAt: string
  updatedAt: string
}

export interface MarketData {
  market: string
  propertyType: PropertyType
  averageCapRate: number
  averageRentPsf: number
  vacancyRate: number
  marketGrowth: number
  lastUpdated: string
}

// Input validation types
export interface ValidationError {
  field: string
  message: string
  code: string
}

export interface ValidationResult {
  isValid: boolean
  errors: ValidationError[]
}

// Security types
export interface SecurityContext {
  ipAddress: string
  userAgent: string
  requestId: string
  sessionId?: string
  riskScore: number
}

export interface EncryptionKeyConfig {
  keyName: string
  algorithm: 'AES-256'
  createdAt: string
  rotationSchedule?: string
}