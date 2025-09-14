/**
 * Secure Storage Library
 * Encrypted data storage with audit logging for Fynsor Consulting
 */

import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';
import { encryptionService, databaseEncryption, keyRotation, SecureHash } from './encryption';
import crypto from 'crypto';

// Storage schemas
const AuditLogSchema = z.object({
  id: z.string(),
  userId: z.string(),
  action: z.enum(['create', 'read', 'update', 'delete', 'export']),
  resource: z.string(),
  resourceId: z.string(),
  ipAddress: z.string().ip(),
  userAgent: z.string(),
  timestamp: z.date(),
  success: z.boolean(),
  errorMessage: z.string().optional(),
  metadata: z.record(z.any()).optional(),
});

const StorageConfigSchema = z.object({
  encrypt: z.boolean().default(true),
  audit: z.boolean().default(true),
  versioning: z.boolean().default(false),
  backup: z.boolean().default(true),
  sensitiveFields: z.array(z.string()).default([]),
});

export type AuditLog = z.infer<typeof AuditLogSchema>;
export type StorageConfig = z.infer<typeof StorageConfigSchema>;

// Secure storage service
export class SecureStorage {
  private supabase: ReturnType<typeof createClient>;
  private config: StorageConfig;

  constructor(config: Partial<StorageConfig> = {}) {
    this.supabase = createClient(
      process.env.SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_KEY!
    );

    this.config = StorageConfigSchema.parse(config);
  }

  // Store data securely
  async store<T>(
    table: string,
    data: T,
    userId: string,
    context: {
      ipAddress: string;
      userAgent: string;
      metadata?: Record<string, any>;
    }
  ): Promise<{ id: string; success: boolean; error?: string }> {
    try {
      // Generate unique ID
      const id = crypto.randomUUID();

      // Prepare data for storage
      let dataToStore = { ...data, id };

      // Encrypt sensitive fields if configured
      if (this.config.encrypt && this.config.sensitiveFields.length > 0) {
        dataToStore = databaseEncryption.encryptForStorage(dataToStore, this.config.sensitiveFields);
      }

      // Add metadata
      const storageData = {
        ...dataToStore,
        created_at: new Date().toISOString(),
        created_by: userId,
        version: 1,
        checksum: this.calculateChecksum(dataToStore),
      };

      // Store in database
      const { error } = await this.supabase
        .from(table)
        .insert(storageData);

      if (error) {
        await this.auditLog(userId, 'create', table, id, context, false, error.message);
        return { id, success: false, error: error.message };
      }

      // Create backup if configured
      if (this.config.backup) {
        await this.createBackup(table, id, storageData);
      }

      // Audit log
      if (this.config.audit) {
        await this.auditLog(userId, 'create', table, id, context, true);
      }

      return { id, success: true };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      await this.auditLog(userId, 'create', table, 'unknown', context, false, errorMessage);
      return { id: 'unknown', success: false, error: errorMessage };
    }
  }

  // Retrieve data securely
  async retrieve<T>(
    table: string,
    id: string,
    userId: string,
    context: {
      ipAddress: string;
      userAgent: string;
      metadata?: Record<string, any>;
    }
  ): Promise<{ data: T | null; success: boolean; error?: string }> {
    try {
      // Retrieve from database
      const { data, error } = await this.supabase
        .from(table)
        .select('*')
        .eq('id', id)
        .single();

      if (error || !data) {
        await this.auditLog(userId, 'read', table, id, context, false, error?.message || 'Record not found');
        return { data: null, success: false, error: error?.message || 'Record not found' };
      }

      // Verify checksum
      const { checksum, ...dataWithoutChecksum } = data;
      if (checksum && !this.verifyChecksum(dataWithoutChecksum, checksum)) {
        await this.auditLog(userId, 'read', table, id, context, false, 'Data integrity check failed');
        return { data: null, success: false, error: 'Data integrity check failed' };
      }

      // Decrypt sensitive fields if necessary
      let decryptedData = data;
      if (this.config.encrypt && data._encrypted_fields) {
        decryptedData = databaseEncryption.decryptFromStorage(data);
      }

      // Remove metadata fields
      const { created_at, created_by, version, ...cleanData } = decryptedData;

      // Audit log
      if (this.config.audit) {
        await this.auditLog(userId, 'read', table, id, context, true);
      }

      return { data: cleanData as T, success: true };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      await this.auditLog(userId, 'read', table, id, context, false, errorMessage);
      return { data: null, success: false, error: errorMessage };
    }
  }

  // Update data securely
  async update<T>(
    table: string,
    id: string,
    updates: Partial<T>,
    userId: string,
    context: {
      ipAddress: string;
      userAgent: string;
      metadata?: Record<string, any>;
    }
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Get current data for versioning
      const { data: currentData } = await this.supabase
        .from(table)
        .select('*')
        .eq('id', id)
        .single();

      if (!currentData) {
        await this.auditLog(userId, 'update', table, id, context, false, 'Record not found');
        return { success: false, error: 'Record not found' };
      }

      // Create version backup if versioning is enabled
      if (this.config.versioning) {
        await this.createVersionBackup(table, id, currentData);
      }

      // Prepare updates
      let updatesToApply = { ...updates };

      // Encrypt sensitive fields if configured
      if (this.config.encrypt && this.config.sensitiveFields.length > 0) {
        updatesToApply = databaseEncryption.encryptForStorage(updatesToApply, this.config.sensitiveFields);
      }

      // Add metadata
      const updateData = {
        ...updatesToApply,
        updated_at: new Date().toISOString(),
        updated_by: userId,
        version: (currentData.version || 1) + 1,
      };

      // Calculate new checksum
      const dataForChecksum = { ...currentData, ...updateData };
      updateData.checksum = this.calculateChecksum(dataForChecksum);

      // Update in database
      const { error } = await this.supabase
        .from(table)
        .update(updateData)
        .eq('id', id);

      if (error) {
        await this.auditLog(userId, 'update', table, id, context, false, error.message);
        return { success: false, error: error.message };
      }

      // Audit log
      if (this.config.audit) {
        await this.auditLog(userId, 'update', table, id, context, true, undefined, {
          updated_fields: Object.keys(updates),
          old_version: currentData.version || 1,
          new_version: updateData.version,
        });
      }

      return { success: true };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      await this.auditLog(userId, 'update', table, id, context, false, errorMessage);
      return { success: false, error: errorMessage };
    }
  }

  // Delete data securely
  async delete(
    table: string,
    id: string,
    userId: string,
    context: {
      ipAddress: string;
      userAgent: string;
      metadata?: Record<string, any>;
    }
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Get current data for backup
      const { data: currentData } = await this.supabase
        .from(table)
        .select('*')
        .eq('id', id)
        .single();

      if (!currentData) {
        await this.auditLog(userId, 'delete', table, id, context, false, 'Record not found');
        return { success: false, error: 'Record not found' };
      }

      // Create deletion backup
      await this.createDeletionBackup(table, id, currentData);

      // Soft delete (mark as deleted instead of actual deletion for audit purposes)
      const { error } = await this.supabase
        .from(table)
        .update({
          deleted_at: new Date().toISOString(),
          deleted_by: userId,
          status: 'deleted',
        })
        .eq('id', id);

      if (error) {
        await this.auditLog(userId, 'delete', table, id, context, false, error.message);
        return { success: false, error: error.message };
      }

      // Audit log
      if (this.config.audit) {
        await this.auditLog(userId, 'delete', table, id, context, true);
      }

      return { success: true };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      await this.auditLog(userId, 'delete', table, id, context, false, errorMessage);
      return { success: false, error: errorMessage };
    }
  }

  // Search data with encryption support
  async search<T>(
    table: string,
    filters: Record<string, any>,
    userId: string,
    context: {
      ipAddress: string;
      userAgent: string;
      metadata?: Record<string, any>;
    },
    options: {
      limit?: number;
      offset?: number;
      orderBy?: string;
      orderDirection?: 'asc' | 'desc';
    } = {}
  ): Promise<{ data: T[]; success: boolean; error?: string; count?: number }> {
    try {
      let query = this.supabase
        .from(table)
        .select('*', { count: 'exact' });

      // Apply filters (note: encrypted fields cannot be filtered directly)
      Object.entries(filters).forEach(([key, value]) => {
        if (!this.config.sensitiveFields.includes(key)) {
          query = query.eq(key, value);
        }
      });

      // Apply soft delete filter
      query = query.neq('status', 'deleted');

      // Apply ordering
      if (options.orderBy) {
        query = query.order(options.orderBy, {
          ascending: options.orderDirection === 'asc',
        });
      }

      // Apply pagination
      if (options.limit) {
        query = query.limit(options.limit);
      }
      if (options.offset) {
        query = query.range(options.offset, (options.offset + (options.limit || 10)) - 1);
      }

      const { data, error, count } = await query;

      if (error) {
        await this.auditLog(userId, 'read', table, 'search', context, false, error.message);
        return { data: [], success: false, error: error.message };
      }

      // Decrypt data if necessary
      const decryptedData = (data || []).map(item => {
        if (this.config.encrypt && item._encrypted_fields) {
          return databaseEncryption.decryptFromStorage(item);
        }
        return item;
      });

      // Audit log
      if (this.config.audit) {
        await this.auditLog(userId, 'read', table, 'search', context, true, undefined, {
          filters,
          result_count: decryptedData.length,
        });
      }

      return { data: decryptedData as T[], success: true, count: count || 0 };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      await this.auditLog(userId, 'read', table, 'search', context, false, errorMessage);
      return { data: [], success: false, error: errorMessage };
    }
  }

  // Export data (with special audit logging)
  async exportData<T>(
    table: string,
    filters: Record<string, any>,
    userId: string,
    context: {
      ipAddress: string;
      userAgent: string;
      metadata?: Record<string, any>;
    }
  ): Promise<{ data: T[]; success: boolean; error?: string }> {
    try {
      const result = await this.search<T>(table, filters, userId, context, { limit: 10000 });

      if (result.success) {
        // Special audit log for data export
        await this.auditLog(userId, 'export', table, 'bulk', context, true, undefined, {
          export_count: result.data.length,
          filters,
        });
      }

      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      await this.auditLog(userId, 'export', table, 'bulk', context, false, errorMessage);
      return { data: [], success: false, error: errorMessage };
    }
  }

  // Audit logging
  private async auditLog(
    userId: string,
    action: AuditLog['action'],
    resource: string,
    resourceId: string,
    context: {
      ipAddress: string;
      userAgent: string;
      metadata?: Record<string, any>;
    },
    success: boolean,
    errorMessage?: string,
    additionalMetadata?: Record<string, any>
  ): Promise<void> {
    try {
      const auditRecord: Omit<AuditLog, 'id'> = {
        userId,
        action,
        resource,
        resourceId,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        timestamp: new Date(),
        success,
        errorMessage,
        metadata: {
          ...context.metadata,
          ...additionalMetadata,
        },
      };

      await this.supabase
        .from('audit_logs')
        .insert({
          id: crypto.randomUUID(),
          user_id: auditRecord.userId,
          action: auditRecord.action,
          resource: auditRecord.resource,
          resource_id: auditRecord.resourceId,
          ip_address: auditRecord.ipAddress,
          user_agent: auditRecord.userAgent,
          timestamp: auditRecord.timestamp.toISOString(),
          success: auditRecord.success,
          error_message: auditRecord.errorMessage,
          metadata: auditRecord.metadata,
        });
    } catch (error) {
      console.error('Failed to create audit log:', error);
    }
  }

  // Calculate data checksum for integrity verification
  private calculateChecksum(data: any): string {
    const serialized = JSON.stringify(data, Object.keys(data).sort());
    return crypto.createHash('sha256').update(serialized).digest('hex');
  }

  // Verify data checksum
  private verifyChecksum(data: any, expectedChecksum: string): boolean {
    const calculatedChecksum = this.calculateChecksum(data);
    return calculatedChecksum === expectedChecksum;
  }

  // Create backup
  private async createBackup(table: string, id: string, data: any): Promise<void> {
    try {
      await this.supabase
        .from('data_backups')
        .insert({
          id: crypto.randomUUID(),
          original_table: table,
          original_id: id,
          backup_data: data,
          backup_type: 'create',
          created_at: new Date().toISOString(),
        });
    } catch (error) {
      console.error('Failed to create backup:', error);
    }
  }

  // Create version backup
  private async createVersionBackup(table: string, id: string, data: any): Promise<void> {
    try {
      await this.supabase
        .from('data_versions')
        .insert({
          id: crypto.randomUUID(),
          original_table: table,
          original_id: id,
          version_data: data,
          version_number: data.version || 1,
          created_at: new Date().toISOString(),
        });
    } catch (error) {
      console.error('Failed to create version backup:', error);
    }
  }

  // Create deletion backup
  private async createDeletionBackup(table: string, id: string, data: any): Promise<void> {
    try {
      await this.supabase
        .from('deleted_data')
        .insert({
          id: crypto.randomUUID(),
          original_table: table,
          original_id: id,
          deleted_data: data,
          deleted_at: new Date().toISOString(),
        });
    } catch (error) {
      console.error('Failed to create deletion backup:', error);
    }
  }
}

// GDPR/CCPA Compliance Helper
export class DataPrivacyManager {
  private storage: SecureStorage;

  constructor() {
    this.storage = new SecureStorage({
      encrypt: true,
      audit: true,
      versioning: true,
      backup: true,
      sensitiveFields: ['email', 'phone', 'address', 'ssn', 'tax_id', 'bank_account'],
    });
  }

  // Request data export (GDPR Article 20)
  async requestDataExport(
    userId: string,
    requestingUserId: string,
    context: { ipAddress: string; userAgent: string }
  ): Promise<{ data: any; success: boolean; error?: string }> {
    // Verify the user can request this data
    if (userId !== requestingUserId) {
      // Additional authorization checks would go here
    }

    const tables = ['users', 'submissions', 'contacts', 'documents'];
    const exportData: Record<string, any> = {};

    for (const table of tables) {
      const result = await this.storage.search(
        table,
        { user_id: userId },
        requestingUserId,
        context
      );

      if (result.success) {
        exportData[table] = result.data;
      }
    }

    return { data: exportData, success: true };
  }

  // Request data deletion (GDPR Article 17)
  async requestDataDeletion(
    userId: string,
    requestingUserId: string,
    context: { ipAddress: string; userAgent: string }
  ): Promise<{ success: boolean; error?: string }> {
    // Verify the user can delete this data
    if (userId !== requestingUserId) {
      // Additional authorization checks would go here
    }

    const tables = ['users', 'submissions', 'contacts', 'documents'];
    let allSuccess = true;
    let errors: string[] = [];

    for (const table of tables) {
      const searchResult = await this.storage.search(
        table,
        { user_id: userId },
        requestingUserId,
        context
      );

      if (searchResult.success) {
        for (const record of searchResult.data) {
          const deleteResult = await this.storage.delete(
            table,
            record.id,
            requestingUserId,
            context
          );

          if (!deleteResult.success) {
            allSuccess = false;
            errors.push(`Failed to delete ${table}:${record.id} - ${deleteResult.error}`);
          }
        }
      }
    }

    return {
      success: allSuccess,
      error: errors.length > 0 ? errors.join('; ') : undefined,
    };
  }

  // Data retention cleanup
  async cleanupExpiredData(): Promise<void> {
    const retentionDays = parseInt(process.env.PII_RETENTION_DAYS || '2555');
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    // This would implement automatic cleanup of old data
    console.log(`Cleaning up data older than ${cutoffDate.toISOString()}`);
  }
}

// Export instances
export const secureStorage = new SecureStorage();
export const dataPrivacyManager = new DataPrivacyManager();