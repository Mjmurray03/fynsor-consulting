import { createHash, randomBytes } from 'crypto';
import { encryptionManager } from './encryption.config';

export interface DataProtectionConfig {
  pii: {
    encryptionRequired: boolean;
    tokenizationEnabled: boolean;
    maskingRules: MaskingRule[];
    retentionPeriod: number; // days
  };
  gdpr: {
    enabled: boolean;
    consentRequired: boolean;
    dataPortabilityEnabled: boolean;
    rightToErasureEnabled: boolean;
    dataMinimization: boolean;
  };
  ccpa: {
    enabled: boolean;
    doNotSell: boolean;
    rightToDelete: boolean;
    rightToKnow: boolean;
  };
  dataResidency: {
    enabled: boolean;
    allowedRegions: string[];
    defaultRegion: string;
  };
  audit: {
    logAllAccess: boolean;
    retentionPeriod: number; // days
    encryptLogs: boolean;
  };
}

export interface MaskingRule {
  field: string;
  method: 'partial' | 'full' | 'hash' | 'tokenize';
  pattern?: string;
  replacement?: string;
}

export interface PIIData {
  id: string;
  type: PIIType;
  value: string;
  encrypted: boolean;
  tokenized: boolean;
  consentId?: string;
  region: string;
  createdAt: Date;
  lastAccessed: Date;
  retentionUntil: Date;
}

export interface ConsentRecord {
  id: string;
  userId: string;
  purposes: string[];
  granular: boolean;
  granted: boolean;
  grantedAt: Date;
  withdrawnAt?: Date;
  ipAddress: string;
  userAgent: string;
  legalBasis: string;
}

export interface DataSubjectRequest {
  id: string;
  userId: string;
  type: 'access' | 'portability' | 'rectification' | 'erasure' | 'restriction';
  status: 'pending' | 'processing' | 'completed' | 'rejected';
  requestedAt: Date;
  completedAt?: Date;
  verificationMethod: string;
  data?: any;
}

export interface AuditLog {
  id: string;
  userId?: string;
  action: string;
  resourceType: string;
  resourceId: string;
  timestamp: Date;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  details: any;
  risk: 'low' | 'medium' | 'high';
}

export type PIIType = 
  | 'email'
  | 'phone'
  | 'ssn'
  | 'passport'
  | 'driverlicense'
  | 'creditcard'
  | 'bankaccount'
  | 'name'
  | 'address'
  | 'birthdate'
  | 'financial'
  | 'biometric'
  | 'custom';

export const DATA_PROTECTION_CONFIG: DataProtectionConfig = {
  pii: {
    encryptionRequired: true,
    tokenizationEnabled: true,
    maskingRules: [
      { field: 'email', method: 'partial', pattern: '(.{2}).*@(.*)' },
      { field: 'phone', method: 'partial', pattern: '(.{3}).*(.{4})' },
      { field: 'ssn', method: 'partial', pattern: 'XXX-XX-(.{4})' },
      { field: 'creditcard', method: 'partial', pattern: '****-****-****-(.{4})' },
      { field: 'name', method: 'partial', pattern: '(.{1})***' }
    ],
    retentionPeriod: parseInt(process.env.PII_RETENTION_DAYS || '2555') // 7 years default
  },
  gdpr: {
    enabled: process.env.GDPR_ENABLED !== 'false',
    consentRequired: true,
    dataPortabilityEnabled: true,
    rightToErasureEnabled: true,
    dataMinimization: true
  },
  ccpa: {
    enabled: process.env.CCPA_ENABLED === 'true',
    doNotSell: true,
    rightToDelete: true,
    rightToKnow: true
  },
  dataResidency: {
    enabled: process.env.DATA_RESIDENCY_ENABLED === 'true',
    allowedRegions: (process.env.ALLOWED_DATA_REGIONS || 'us,eu').split(','),
    defaultRegion: process.env.DEFAULT_DATA_REGION || 'us'
  },
  audit: {
    logAllAccess: true,
    retentionPeriod: parseInt(process.env.AUDIT_RETENTION_DAYS || '2555'), // 7 years
    encryptLogs: true
  }
};

export class DataProtectionManager {
  private static instance: DataProtectionManager;
  private tokenRegistry: Map<string, string> = new Map();
  private consentStore: Map<string, ConsentRecord> = new Map();
  private auditBuffer: AuditLog[] = [];
  private cleanupInterval: NodeJS.Timeout;

  private constructor() {
    this.startCleanupScheduler();
    this.startAuditLogFlush();
  }

  public static getInstance(): DataProtectionManager {
    if (!DataProtectionManager.instance) {
      DataProtectionManager.instance = new DataProtectionManager();
    }
    return DataProtectionManager.instance;
  }

  public async encryptPII(data: any, piiType: PIIType, userId?: string, region?: string): Promise<PIIData> {
    try {
      const id = this.generateDataId();
      const encrypted = await encryptionManager.encryptPII(data);
      
      const piiData: PIIData = {
        id,
        type: piiType,
        value: encrypted,
        encrypted: true,
        tokenized: false,
        region: region || DATA_PROTECTION_CONFIG.dataResidency.defaultRegion,
        createdAt: new Date(),
        lastAccessed: new Date(),
        retentionUntil: this.calculateRetentionDate()
      };

      if (userId) {
        await this.logDataAccess(userId, 'ENCRYPT_PII', piiType, id, 'medium');
      }

      return piiData;
    } catch (error) {
      console.error('[DATA_PROTECTION] PII encryption failed:', error);
      throw new Error('Failed to encrypt PII data');
    }
  }

  public async decryptPII(piiData: PIIData, userId?: string): Promise<any> {
    try {
      if (!piiData.encrypted) {
        throw new Error('Data is not encrypted');
      }

      const decrypted = await encryptionManager.decryptPII(piiData.value);
      
      // Update last accessed
      piiData.lastAccessed = new Date();

      if (userId) {
        await this.logDataAccess(userId, 'DECRYPT_PII', piiData.type, piiData.id, 'high');
      }

      return decrypted;
    } catch (error) {
      console.error('[DATA_PROTECTION] PII decryption failed:', error);
      throw new Error('Failed to decrypt PII data');
    }
  }

  public tokenizePII(data: string, piiType: PIIType): string {
    const token = `tok_${piiType}_${encryptionManager.generateSecureToken(32)}`;
    this.tokenRegistry.set(token, data);
    return token;
  }

  public detokenizePII(token: string, userId?: string): string | null {
    if (!token.startsWith('tok_')) {
      return null;
    }

    const data = this.tokenRegistry.get(token);
    if (data && userId) {
      this.logDataAccess(userId, 'DETOKENIZE_PII', 'unknown', token, 'medium');
    }

    return data || null;
  }

  public maskPII(data: string, piiType: PIIType): string {
    const rule = DATA_PROTECTION_CONFIG.pii.maskingRules.find(r => r.field === piiType);
    if (!rule) {
      return '***';
    }

    switch (rule.method) {
      case 'full':
        return '*'.repeat(data.length);
      case 'hash':
        return createHash('sha256').update(data).digest('hex').substring(0, 8);
      case 'partial':
        return this.applyPartialMasking(data, rule.pattern || '');
      default:
        return data;
    }
  }

  public async recordConsent(userId: string, purposes: string[], ipAddress: string, userAgent: string, legalBasis: string = 'consent'): Promise<ConsentRecord> {
    const consent: ConsentRecord = {
      id: this.generateConsentId(),
      userId,
      purposes,
      granular: purposes.length > 1,
      granted: true,
      grantedAt: new Date(),
      ipAddress,
      userAgent,
      legalBasis
    };

    this.consentStore.set(consent.id, consent);
    await this.logDataAccess(userId, 'CONSENT_GRANTED', 'consent', consent.id, 'low');

    return consent;
  }

  public async withdrawConsent(userId: string, consentId: string): Promise<boolean> {
    const consent = this.consentStore.get(consentId);
    if (!consent || consent.userId !== userId) {
      return false;
    }

    consent.withdrawnAt = new Date();
    consent.granted = false;
    this.consentStore.set(consentId, consent);

    await this.logDataAccess(userId, 'CONSENT_WITHDRAWN', 'consent', consentId, 'medium');
    return true;
  }

  public hasValidConsent(userId: string, purpose: string): boolean {
    for (const consent of this.consentStore.values()) {
      if (consent.userId === userId && 
          consent.granted && 
          !consent.withdrawnAt &&
          consent.purposes.includes(purpose)) {
        return true;
      }
    }
    return false;
  }

  public async createDataSubjectRequest(userId: string, type: DataSubjectRequest['type'], verificationMethod: string): Promise<DataSubjectRequest> {
    const request: DataSubjectRequest = {
      id: this.generateRequestId(),
      userId,
      type,
      status: 'pending',
      requestedAt: new Date(),
      verificationMethod
    };

    await this.logDataAccess(userId, 'DATA_SUBJECT_REQUEST', type, request.id, 'high');
    return request;
  }

  public async processDataSubjectRequest(requestId: string): Promise<void> {
    // Implementation would depend on your data architecture
    // This is a placeholder for the actual data processing logic
    throw new Error('Data subject request processing not implemented');
  }

  public async exportUserData(userId: string, format: 'json' | 'csv' | 'xml' = 'json'): Promise<any> {
    try {
      // Collect all user data from various sources
      const userData = {
        profile: await this.getUserProfile(userId),
        consents: Array.from(this.consentStore.values()).filter(c => c.userId === userId),
        auditLogs: this.auditBuffer.filter(log => log.userId === userId),
        exportedAt: new Date().toISOString(),
        format
      };

      await this.logDataAccess(userId, 'DATA_EXPORT', 'user_data', userId, 'medium');
      return userData;
    } catch (error) {
      console.error('[DATA_PROTECTION] Data export failed:', error);
      throw new Error('Failed to export user data');
    }
  }

  public async eraseUserData(userId: string, verificationToken: string): Promise<boolean> {
    try {
      // Verify the erasure request
      if (!this.verifyErasureToken(userId, verificationToken)) {
        return false;
      }

      // Remove user data (implement based on your data architecture)
      await this.removeUserPII(userId);
      await this.removeUserConsents(userId);
      await this.anonymizeAuditLogs(userId);

      await this.logDataAccess(userId, 'DATA_ERASURE', 'user_data', userId, 'high');
      return true;
    } catch (error) {
      console.error('[DATA_PROTECTION] Data erasure failed:', error);
      return false;
    }
  }

  public async logDataAccess(userId: string, action: string, resourceType: string, resourceId: string, risk: 'low' | 'medium' | 'high', details?: any): Promise<void> {
    const auditLog: AuditLog = {
      id: this.generateAuditId(),
      userId,
      action,
      resourceType,
      resourceId,
      timestamp: new Date(),
      ipAddress: 'unknown', // This should be passed from the request context
      userAgent: 'unknown', // This should be passed from the request context
      success: true,
      details: details || {},
      risk
    };

    this.auditBuffer.push(auditLog);
  }

  public getDataRetentionPolicy(dataType: string): number {
    switch (dataType) {
      case 'pii':
        return DATA_PROTECTION_CONFIG.pii.retentionPeriod;
      case 'audit':
        return DATA_PROTECTION_CONFIG.audit.retentionPeriod;
      default:
        return 365; // 1 year default
    }
  }

  public isDataResidencyCompliant(region: string): boolean {
    if (!DATA_PROTECTION_CONFIG.dataResidency.enabled) {
      return true;
    }
    return DATA_PROTECTION_CONFIG.dataResidency.allowedRegions.includes(region);
  }

  private applyPartialMasking(data: string, pattern: string): string {
    try {
      const regex = new RegExp(pattern);
      return data.replace(regex, (match, ...groups) => {
        return groups.map((group, index) => 
          index < groups.length - 2 ? group : '*'.repeat(group?.length || 0)
        ).join('');
      });
    } catch {
      return '***';
    }
  }

  private calculateRetentionDate(): Date {
    const date = new Date();
    date.setDate(date.getDate() + DATA_PROTECTION_CONFIG.pii.retentionPeriod);
    return date;
  }

  private generateDataId(): string {
    return `pii_${Date.now()}_${encryptionManager.generateSecureToken(16)}`;
  }

  private generateConsentId(): string {
    return `consent_${Date.now()}_${encryptionManager.generateSecureToken(16)}`;
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${encryptionManager.generateSecureToken(16)}`;
  }

  private generateAuditId(): string {
    return `audit_${Date.now()}_${encryptionManager.generateSecureToken(16)}`;
  }

  private async getUserProfile(userId: string): Promise<any> {
    // Implement user profile retrieval
    return { id: userId, message: 'User profile retrieval not implemented' };
  }

  private verifyErasureToken(userId: string, token: string): boolean {
    // Implement token verification logic
    return true; // Placeholder
  }

  private async removeUserPII(userId: string): Promise<void> {
    // Remove all PII data associated with the user
    console.log(`Removing PII data for user: ${userId}`);
  }

  private async removeUserConsents(userId: string): Promise<void> {
    // Remove consent records
    for (const [id, consent] of this.consentStore.entries()) {
      if (consent.userId === userId) {
        this.consentStore.delete(id);
      }
    }
  }

  private async anonymizeAuditLogs(userId: string): Promise<void> {
    // Anonymize audit logs by removing user ID
    this.auditBuffer = this.auditBuffer.map(log => 
      log.userId === userId ? { ...log, userId: 'anonymized' } : log
    );
  }

  private startCleanupScheduler(): void {
    // Run cleanup daily
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredData();
    }, 24 * 60 * 60 * 1000);
  }

  private startAuditLogFlush(): void {
    // Flush audit logs every 5 minutes
    setInterval(() => {
      this.flushAuditLogs();
    }, 5 * 60 * 1000);
  }

  private async cleanupExpiredData(): Promise<void> {
    const now = new Date();
    
    // Clean up expired tokens
    for (const [token, data] of this.tokenRegistry.entries()) {
      // Implement token expiration logic
    }

    // Clean up old audit logs
    const auditRetentionDate = new Date();
    auditRetentionDate.setDate(auditRetentionDate.getDate() - DATA_PROTECTION_CONFIG.audit.retentionPeriod);
    
    this.auditBuffer = this.auditBuffer.filter(log => log.timestamp > auditRetentionDate);
  }

  private async flushAuditLogs(): Promise<void> {
    if (this.auditBuffer.length === 0) return;

    const logsToFlush = [...this.auditBuffer];
    this.auditBuffer = [];

    try {
      // Store audit logs in persistent storage
      if (DATA_PROTECTION_CONFIG.audit.encryptLogs) {
        const encryptedLogs = await encryptionManager.encryptPII(JSON.stringify(logsToFlush));
        // Store encryptedLogs in your database
        console.log(`Flushing ${logsToFlush.length} encrypted audit logs`);
      } else {
        // Store logsToFlush in your database
        console.log(`Flushing ${logsToFlush.length} audit logs`);
      }
    } catch (error) {
      console.error('[DATA_PROTECTION] Failed to flush audit logs:', error);
      // Re-add logs to buffer for retry
      this.auditBuffer.unshift(...logsToFlush);
    }
  }

  public destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }
}

export const dataProtectionManager = DataProtectionManager.getInstance();