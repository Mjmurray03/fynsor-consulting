/**
 * Data Encryption Library
 * Military-grade encryption for Fynsor Consulting data protection
 */

import crypto from 'crypto';
import { z } from 'zod';

// Encryption configuration
const ENCRYPTION_CONFIG = {
  algorithm: 'aes-256-gcm' as const,
  keyLength: 32,
  ivLength: 16,
  tagLength: 16,
  saltLength: 32,
  iterations: 100000, // PBKDF2 iterations
} as const;

// Encryption schemas
const EncryptedDataSchema = z.object({
  data: z.string(),
  iv: z.string(),
  tag: z.string(),
  salt: z.string().optional(),
});

const EncryptionKeySchema = z.object({
  key: z.string(),
  salt: z.string(),
  iterations: z.number(),
});

export type EncryptedData = z.infer<typeof EncryptedDataSchema>;
export type EncryptionKey = z.infer<typeof EncryptionKeySchema>;

// Key derivation functions
export class KeyDerivation {
  // Derive key from password using PBKDF2
  static deriveKeyFromPassword(
    password: string,
    salt?: Buffer,
    iterations: number = ENCRYPTION_CONFIG.iterations
  ): EncryptionKey {
    const keySalt = salt || crypto.randomBytes(ENCRYPTION_CONFIG.saltLength);
    const key = crypto.pbkdf2Sync(
      password,
      keySalt,
      iterations,
      ENCRYPTION_CONFIG.keyLength,
      'sha512'
    );

    return {
      key: key.toString('base64'),
      salt: keySalt.toString('base64'),
      iterations,
    };
  }

  // Generate random key
  static generateRandomKey(): string {
    return crypto.randomBytes(ENCRYPTION_CONFIG.keyLength).toString('base64');
  }

  // Derive key from master key and context
  static deriveContextKey(masterKey: string, context: string): string {
    const hmac = crypto.createHmac('sha256', Buffer.from(masterKey, 'base64'));
    hmac.update(context);
    return hmac.digest('base64');
  }
}

// AES-GCM Encryption Service
export class AESGCMService {
  private masterKey: Buffer;

  constructor(masterKey?: string) {
    this.masterKey = masterKey
      ? Buffer.from(masterKey, 'base64')
      : Buffer.from(process.env.ENCRYPTION_MASTER_KEY || KeyDerivation.generateRandomKey(), 'base64');
  }

  // Encrypt data with AES-256-GCM
  encrypt(plaintext: string, context?: string): EncryptedData {
    try {
      // Use context-specific key if provided
      const key = context
        ? Buffer.from(KeyDerivation.deriveContextKey(this.masterKey.toString('base64'), context), 'base64')
        : this.masterKey;

      const iv = crypto.randomBytes(ENCRYPTION_CONFIG.ivLength);
      const cipher = crypto.createCipherGCM(ENCRYPTION_CONFIG.algorithm, key, iv);

      let encrypted = cipher.update(plaintext, 'utf8', 'base64');
      encrypted += cipher.final('base64');

      const tag = cipher.getAuthTag();

      return {
        data: encrypted,
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
      };
    } catch (error) {
      throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Decrypt data with AES-256-GCM
  decrypt(encryptedData: EncryptedData, context?: string): string {
    try {
      EncryptedDataSchema.parse(encryptedData);

      // Use context-specific key if provided
      const key = context
        ? Buffer.from(KeyDerivation.deriveContextKey(this.masterKey.toString('base64'), context), 'base64')
        : this.masterKey;

      const iv = Buffer.from(encryptedData.iv, 'base64');
      const tag = Buffer.from(encryptedData.tag, 'base64');
      const decipher = crypto.createDecipherGCM(ENCRYPTION_CONFIG.algorithm, key, iv);

      decipher.setAuthTag(tag);

      let decrypted = decipher.update(encryptedData.data, 'base64', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Encrypt with password
  encryptWithPassword(plaintext: string, password: string): EncryptedData {
    const keyData = KeyDerivation.deriveKeyFromPassword(password);
    const key = Buffer.from(keyData.key, 'base64');

    const iv = crypto.randomBytes(ENCRYPTION_CONFIG.ivLength);
    const cipher = crypto.createCipherGCM(ENCRYPTION_CONFIG.algorithm, key, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    const tag = cipher.getAuthTag();

    return {
      data: encrypted,
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      salt: keyData.salt,
    };
  }

  // Decrypt with password
  decryptWithPassword(encryptedData: EncryptedData, password: string): string {
    if (!encryptedData.salt) {
      throw new Error('Salt required for password decryption');
    }

    const keyData = KeyDerivation.deriveKeyFromPassword(
      password,
      Buffer.from(encryptedData.salt, 'base64'),
      ENCRYPTION_CONFIG.iterations
    );

    const key = Buffer.from(keyData.key, 'base64');
    const iv = Buffer.from(encryptedData.iv, 'base64');
    const tag = Buffer.from(encryptedData.tag, 'base64');

    const decipher = crypto.createDecipherGCM(ENCRYPTION_CONFIG.algorithm, key, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encryptedData.data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

// Client-side encryption service
export class ClientSideEncryption {
  private static readonly BROWSER_KEY_STORAGE = 'fynsor_client_key';

  // Generate ephemeral key for client-side encryption
  static generateEphemeralKey(): string {
    // In browser environment, use crypto.getRandomValues
    if (typeof window !== 'undefined' && window.crypto?.getRandomValues) {
      const array = new Uint8Array(32);
      window.crypto.getRandomValues(array);
      return btoa(String.fromCharCode(...array));
    }

    // Fallback for Node.js
    return crypto.randomBytes(32).toString('base64');
  }

  // Store encryption key securely in browser
  static storeKey(key: string): void {
    if (typeof window !== 'undefined') {
      // In production, consider using IndexedDB with additional security
      sessionStorage.setItem(this.BROWSER_KEY_STORAGE, key);
    }
  }

  // Retrieve encryption key from browser
  static retrieveKey(): string | null {
    if (typeof window !== 'undefined') {
      return sessionStorage.getItem(this.BROWSER_KEY_STORAGE);
    }
    return null;
  }

  // Clear stored key
  static clearKey(): void {
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem(this.BROWSER_KEY_STORAGE);
    }
  }

  // Encrypt form data before submission
  static encryptFormData(data: Record<string, any>): EncryptedData {
    const key = this.retrieveKey();
    if (!key) {
      throw new Error('No encryption key available');
    }

    const aes = new AESGCMService(key);
    return aes.encrypt(JSON.stringify(data), 'form_data');
  }

  // Decrypt form data after retrieval
  static decryptFormData(encryptedData: EncryptedData): Record<string, any> {
    const key = this.retrieveKey();
    if (!key) {
      throw new Error('No encryption key available');
    }

    const aes = new AESGCMService(key);
    const decrypted = aes.decrypt(encryptedData, 'form_data');
    return JSON.parse(decrypted);
  }
}

// Field-level encryption for sensitive data
export class FieldEncryption {
  private aes: AESGCMService;

  constructor(masterKey?: string) {
    this.aes = new AESGCMService(masterKey);
  }

  // Encrypt specific fields in an object
  encryptFields<T extends Record<string, any>>(
    data: T,
    fieldsToEncrypt: (keyof T)[]
  ): T & { _encrypted_fields: string[] } {
    const result = { ...data } as T & { _encrypted_fields: string[] };
    result._encrypted_fields = [];

    fieldsToEncrypt.forEach(field => {
      if (data[field] !== undefined && data[field] !== null) {
        const fieldValue = typeof data[field] === 'string' ? data[field] : JSON.stringify(data[field]);
        const encrypted = this.aes.encrypt(fieldValue, String(field));
        result[field] = encrypted as any;
        result._encrypted_fields.push(String(field));
      }
    });

    return result;
  }

  // Decrypt specific fields in an object
  decryptFields<T extends Record<string, any>>(
    data: T & { _encrypted_fields?: string[] }
  ): T {
    const result = { ...data } as T;
    const encryptedFields = data._encrypted_fields || [];

    encryptedFields.forEach(field => {
      if (data[field] !== undefined && data[field] !== null) {
        const decrypted = this.aes.decrypt(data[field] as EncryptedData, field);
        try {
          // Try to parse as JSON first
          result[field] = JSON.parse(decrypted);
        } catch {
          // If not JSON, use as string
          result[field] = decrypted;
        }
      }
    });

    // Remove metadata
    delete (result as any)._encrypted_fields;

    return result;
  }
}

// Database encryption helper
export class DatabaseEncryption {
  private fieldEncryption: FieldEncryption;

  constructor() {
    this.fieldEncryption = new FieldEncryption();
  }

  // Encrypt data before storing in database
  encryptForStorage(data: any, sensitiveFields: string[]): any {
    if (Array.isArray(data)) {
      return data.map(item => this.encryptForStorage(item, sensitiveFields));
    }

    if (typeof data === 'object' && data !== null) {
      return this.fieldEncryption.encryptFields(data, sensitiveFields);
    }

    return data;
  }

  // Decrypt data after retrieving from database
  decryptFromStorage(data: any): any {
    if (Array.isArray(data)) {
      return data.map(item => this.decryptFromStorage(item));
    }

    if (typeof data === 'object' && data !== null && data._encrypted_fields) {
      return this.fieldEncryption.decryptFields(data);
    }

    return data;
  }
}

// Secure hash functions
export class SecureHash {
  // Create secure hash with salt
  static hash(data: string, salt?: string): { hash: string; salt: string } {
    const hashSalt = salt || crypto.randomBytes(16).toString('base64');
    const hash = crypto.createHash('sha256');
    hash.update(data + hashSalt);

    return {
      hash: hash.digest('base64'),
      salt: hashSalt,
    };
  }

  // Verify hash
  static verify(data: string, hash: string, salt: string): boolean {
    const computed = this.hash(data, salt);
    return this.constantTimeEquals(computed.hash, hash);
  }

  // HMAC for message authentication
  static hmac(message: string, key: string): string {
    return crypto.createHmac('sha256', key).update(message).digest('base64');
  }

  // Verify HMAC
  static verifyHmac(message: string, hmac: string, key: string): boolean {
    const computed = this.hmac(message, key);
    return this.constantTimeEquals(computed, hmac);
  }

  // Constant time string comparison
  private static constantTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }
}

// Key rotation service
export class KeyRotation {
  private currentVersion: number;
  private keys: Map<number, string> = new Map();

  constructor() {
    this.currentVersion = parseInt(process.env.ENCRYPTION_KEY_VERSION || '1');
    this.loadKeys();
  }

  private loadKeys(): void {
    // Load keys from environment or secure key management system
    for (let i = 1; i <= this.currentVersion; i++) {
      const key = process.env[`ENCRYPTION_KEY_V${i}`];
      if (key) {
        this.keys.set(i, key);
      }
    }

    // Ensure current key exists
    if (!this.keys.has(this.currentVersion)) {
      const newKey = KeyDerivation.generateRandomKey();
      this.keys.set(this.currentVersion, newKey);
      console.warn(`Generated new encryption key for version ${this.currentVersion}`);
    }
  }

  // Encrypt with current key version
  encrypt(data: string, context?: string): EncryptedData & { version: number } {
    const key = this.keys.get(this.currentVersion);
    if (!key) {
      throw new Error('Current encryption key not found');
    }

    const aes = new AESGCMService(key);
    const encrypted = aes.encrypt(data, context);

    return {
      ...encrypted,
      version: this.currentVersion,
    };
  }

  // Decrypt with appropriate key version
  decrypt(encryptedData: EncryptedData & { version?: number }, context?: string): string {
    const version = encryptedData.version || 1;
    const key = this.keys.get(version);

    if (!key) {
      throw new Error(`Encryption key version ${version} not found`);
    }

    const aes = new AESGCMService(key);
    return aes.decrypt(encryptedData, context);
  }

  // Rotate to new key version
  rotateKey(): number {
    const newVersion = this.currentVersion + 1;
    const newKey = KeyDerivation.generateRandomKey();

    this.keys.set(newVersion, newKey);
    this.currentVersion = newVersion;

    console.log(`Rotated to key version ${newVersion}`);
    return newVersion;
  }
}

// Export instances and classes
export const encryptionService = new AESGCMService();
export const databaseEncryption = new DatabaseEncryption();
export const keyRotation = new KeyRotation();

// Export utility functions
export { ClientSideEncryption, FieldEncryption, SecureHash, KeyDerivation };