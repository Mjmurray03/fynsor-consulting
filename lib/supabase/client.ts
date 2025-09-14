import { createClient, SupabaseClient } from '@supabase/supabase-js'
import { Database } from './types'

// Environment variables validation
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error('Missing Supabase environment variables')
}

// Client-side Supabase client (with RLS enabled)
export const supabase: SupabaseClient<Database> = createClient(
  supabaseUrl,
  supabaseAnonKey,
  {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
    },
    db: {
      schema: 'public',
    },
    global: {
      headers: {
        'X-Client-Info': 'fynsor-consulting',
      },
    },
  }
)

// Server-side Supabase client (bypasses RLS for admin operations)
export const supabaseAdmin: SupabaseClient<Database> = createClient(
  supabaseUrl,
  supabaseServiceKey || supabaseAnonKey,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
    db: {
      schema: 'public',
    },
    global: {
      headers: {
        'X-Client-Info': 'fynsor-consulting-admin',
      },
    },
  }
)

// Encryption helper functions for PII data
export class EncryptionService {
  private static instance: EncryptionService
  private encryptionKey: string

  private constructor() {
    this.encryptionKey = process.env.ENCRYPTION_KEY || 'default-dev-key-change-in-production'

    if (process.env.NODE_ENV === 'production' && this.encryptionKey === 'default-dev-key-change-in-production') {
      throw new Error('Production encryption key not configured')
    }
  }

  static getInstance(): EncryptionService {
    if (!EncryptionService.instance) {
      EncryptionService.instance = new EncryptionService()
    }
    return EncryptionService.instance
  }

  async encryptPII(data: string, keyName: string = 'default'): Promise<string | null> {
    if (!data || data.trim() === '') {
      return null
    }

    try {
      const { data: result, error } = await supabaseAdmin.rpc('encrypt_pii', {
        data: data.trim(),
        key_name: keyName
      })

      if (error) {
        console.error('Encryption error:', error)
        return null
      }

      return result
    } catch (error) {
      console.error('Encryption failed:', error)
      return null
    }
  }

  async decryptPII(encryptedData: string, keyName: string = 'default'): Promise<string | null> {
    if (!encryptedData || encryptedData.trim() === '') {
      return null
    }

    try {
      const { data: result, error } = await supabaseAdmin.rpc('decrypt_pii', {
        encrypted_data: encryptedData,
        key_name: keyName
      })

      if (error) {
        console.error('Decryption error:', error)
        return null
      }

      return result
    } catch (error) {
      console.error('Decryption failed:', error)
      return null
    }
  }
}

// Audit logging service
export class AuditService {
  static async logEvent(params: {
    action: string
    userId?: string
    userEmail?: string
    userRole?: string
    ipAddress?: string
    userAgent?: string
    requestId?: string
    sessionId?: string
    resourceType?: string
    resourceId?: string
    metadata?: Record<string, any>
    riskScore?: number
  }): Promise<string | null> {
    try {
      const { data: auditId, error } = await supabaseAdmin.rpc('log_audit_event', {
        p_action: params.action,
        p_user_id: params.userId || null,
        p_user_email: params.userEmail || null,
        p_user_role: params.userRole || null,
        p_ip_address: params.ipAddress || null,
        p_user_agent: params.userAgent || null,
        p_request_id: params.requestId || null,
        p_session_id: params.sessionId || null,
        p_resource_type: params.resourceType || null,
        p_resource_id: params.resourceId || null,
        p_metadata: params.metadata || {},
        p_risk_score: params.riskScore || 0
      })

      if (error) {
        console.error('Audit logging error:', error)
        return null
      }

      return auditId
    } catch (error) {
      console.error('Audit logging failed:', error)
      return null
    }
  }
}

// Rate limiting service
export class RateLimitService {
  static async checkRateLimit(
    identifier: string,
    endpoint: string,
    limit: number = 100,
    windowMinutes: number = 60
  ): Promise<boolean> {
    try {
      const { data: allowed, error } = await supabaseAdmin.rpc('check_rate_limit', {
        p_identifier: identifier,
        p_endpoint: endpoint,
        p_limit: limit,
        p_window_minutes: windowMinutes
      })

      if (error) {
        console.error('Rate limit check error:', error)
        // Fail open for availability
        return true
      }

      return allowed || false
    } catch (error) {
      console.error('Rate limit check failed:', error)
      // Fail open for availability
      return true
    }
  }
}

// Contact management service
export class ContactService {
  private encryptionService: EncryptionService

  constructor() {
    this.encryptionService = EncryptionService.getInstance()
  }

  async createContact(contactData: {
    name: string
    email: string
    company?: string
    phone?: string
    message?: string
    propertyType?: string
    investmentSize?: string
    ipAddress?: string
    userAgent?: string
    referrer?: string
    utmSource?: string
    utmMedium?: string
    utmCampaign?: string
  }): Promise<{ success: boolean; contactId?: string; error?: string }> {
    try {
      // Encrypt PII fields
      const [nameEncrypted, emailEncrypted, companyEncrypted, phoneEncrypted, messageEncrypted] =
        await Promise.all([
          this.encryptionService.encryptPII(contactData.name),
          this.encryptionService.encryptPII(contactData.email),
          contactData.company ? this.encryptionService.encryptPII(contactData.company) : Promise.resolve(null),
          contactData.phone ? this.encryptionService.encryptPII(contactData.phone) : Promise.resolve(null),
          contactData.message ? this.encryptionService.encryptPII(contactData.message) : Promise.resolve(null),
        ])

      if (!nameEncrypted || !emailEncrypted) {
        throw new Error('Failed to encrypt required contact data')
      }

      // Insert contact record
      const { data: contact, error } = await supabaseAdmin
        .from('contacts')
        .insert({
          name_encrypted: nameEncrypted,
          email_encrypted: emailEncrypted,
          company_encrypted: companyEncrypted,
          phone_encrypted: phoneEncrypted,
          message_encrypted: messageEncrypted,
          property_type: contactData.propertyType || null,
          investment_size: contactData.investmentSize || null,
          ip_address: contactData.ipAddress || null,
          user_agent: contactData.userAgent || null,
          referrer: contactData.referrer || null,
          utm_source: contactData.utmSource || null,
          utm_medium: contactData.utmMedium || null,
          utm_campaign: contactData.utmCampaign || null,
        })
        .select('id')
        .single()

      if (error) {
        throw error
      }

      // Log audit event
      await AuditService.logEvent({
        action: 'contact_created',
        resourceType: 'contact',
        resourceId: contact.id,
        ipAddress: contactData.ipAddress,
        userAgent: contactData.userAgent,
        metadata: {
          property_type: contactData.propertyType,
          investment_size: contactData.investmentSize,
          has_phone: !!contactData.phone,
          has_company: !!contactData.company,
          utm_source: contactData.utmSource,
        }
      })

      return { success: true, contactId: contact.id }
    } catch (error) {
      console.error('Contact creation failed:', error)

      // Log audit event for failed contact creation
      await AuditService.logEvent({
        action: 'contact_creation_failed',
        ipAddress: contactData.ipAddress,
        userAgent: contactData.userAgent,
        metadata: {
          error: error instanceof Error ? error.message : 'Unknown error',
          property_type: contactData.propertyType,
        },
        riskScore: 25
      })

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      }
    }
  }

  async getContacts(adminUserId?: string, limit: number = 50, offset: number = 0): Promise<{
    success: boolean
    contacts?: Array<{
      id: string
      name: string
      email: string
      company?: string
      phone?: string
      message?: string
      propertyType?: string
      investmentSize?: string
      ipAddress?: string
      createdAt: string
      status: string
    }>
    error?: string
  }> {
    try {
      // Log audit event for data access
      await AuditService.logEvent({
        action: 'contact_viewed',
        userId: adminUserId,
        resourceType: 'contact',
        metadata: { limit, offset }
      })

      // Fetch contacts (encrypted)
      const { data: contacts, error } = await supabaseAdmin
        .from('contacts')
        .select('*')
        .order('created_at', { ascending: false })
        .range(offset, offset + limit - 1)

      if (error) {
        throw error
      }

      // Decrypt PII data for admin viewing
      const decryptedContacts = await Promise.all(
        contacts.map(async (contact) => {
          const [name, email, company, phone, message] = await Promise.all([
            this.encryptionService.decryptPII(contact.name_encrypted),
            this.encryptionService.decryptPII(contact.email_encrypted),
            contact.company_encrypted ? this.encryptionService.decryptPII(contact.company_encrypted) : null,
            contact.phone_encrypted ? this.encryptionService.decryptPII(contact.phone_encrypted) : null,
            contact.message_encrypted ? this.encryptionService.decryptPII(contact.message_encrypted) : null,
          ])

          return {
            id: contact.id,
            name: name || '[Decryption Error]',
            email: email || '[Decryption Error]',
            company: company || undefined,
            phone: phone || undefined,
            message: message || undefined,
            propertyType: contact.property_type,
            investmentSize: contact.investment_size,
            ipAddress: contact.ip_address,
            createdAt: contact.created_at,
            status: contact.status
          }
        })
      )

      return { success: true, contacts: decryptedContacts }
    } catch (error) {
      console.error('Contact retrieval failed:', error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      }
    }
  }
}

// Configuration for setting up the encryption key
export const setupEncryptionKey = async (key: string): Promise<boolean> => {
  try {
    const { error } = await supabaseAdmin.rpc('set_config', {
      setting_name: 'app.encryption_key',
      new_value: key,
      is_local: false
    })

    return !error
  } catch (error) {
    console.error('Failed to set encryption key:', error)
    return false
  }
}

export default supabase