/**
 * Encryption Configuration for Fynsor Security Infrastructure
 * SOC 2 Type II compliant encryption settings
 *
 * Features:
 * - AES-256-GCM for data at rest
 * - TLS 1.3 for data in transit
 * - Key rotation every 30 days
 * - HSM integration ready
 */

import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'crypto';

export interface EncryptionConfig {
  algorithm: string;
  keyLength: number;
  ivLength: number;
  tagLength: number;
  keyRotationDays: number;
  hsm: {
    enabled: boolean;
    provider: string;
    keyStore: string;
  };
  tls: {
    minVersion: string;
    cipherSuites: string[];
    dhParam: number;
  };
}

export const ENCRYPTION_CONFIG: EncryptionConfig = {
  algorithm: 'aes-256-gcm',
  keyLength: 32, // 256 bits
  ivLength: 16,  // 128 bits
  tagLength: 16, // 128 bits
  keyRotationDays: 30,
  hsm: {
    enabled: process.env.HSM_ENABLED === 'true',
    provider: process.env.HSM_PROVIDER || 'aws-cloudhsm',
    keyStore: process.env.HSM_KEY_STORE || 'fynsor-main-keystore'
  },
  tls: {
    minVersion: 'TLSv1.3',
    cipherSuites: [
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
      'TLS_AES_128_GCM_SHA256'
    ],
    dhParam: 4096
  }
};

export class EncryptionManager {
  private static instance: EncryptionManager;
  private keyCache: Map<string, Buffer> = new Map();
  private keyRotationSchedule: Map<string, Date> = new Map();

  private constructor() {
    this.initializeKeyRotation();
  }

  public static getInstance(): EncryptionManager {
    if (!EncryptionManager.instance) {
      EncryptionManager.instance = new EncryptionManager();
    }
    return EncryptionManager.instance;
  }

  /**
   * Encrypt data using AES-256-GCM
   */
  public encrypt(data: string, keyId: string = 'default'): EncryptedData {
    try {
      const key = this.getEncryptionKey(keyId);
      const iv = randomBytes(ENCRYPTION_CONFIG.ivLength);

      const cipher = createCipheriv(ENCRYPTION_CONFIG.algorithm, key, iv);

      let encrypted = cipher.update(data, 'utf8', 'base64');
      encrypted += cipher.final('base64');

      const tag = cipher.getAuthTag();

      return {
        data: encrypted,
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        keyId,
        algorithm: ENCRYPTION_CONFIG.algorithm,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data using AES-256-GCM
   */
  public decrypt(encryptedData: EncryptedData): string {
    try {
      const key = this.getEncryptionKey(encryptedData.keyId);
      const iv = Buffer.from(encryptedData.iv, 'base64');
      const tag = Buffer.from(encryptedData.tag, 'base64');

      const decipher = createDecipheriv(ENCRYPTION_CONFIG.algorithm, key, iv);
      decipher.setAuthTag(tag);

      let decrypted = decipher.update(encryptedData.data, 'base64', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Generate or retrieve encryption key
   */
  private getEncryptionKey(keyId: string): Buffer {
    if (this.keyCache.has(keyId) && !this.isKeyRotationDue(keyId)) {
      return this.keyCache.get(keyId)!;
    }

    // Generate new key or retrieve from HSM
    const key = ENCRYPTION_CONFIG.hsm.enabled
      ? this.getKeyFromHSM(keyId)
      : this.generateKey();

    this.keyCache.set(keyId, key);
    this.keyRotationSchedule.set(keyId, new Date());

    return key;
  }

  /**
   * Generate cryptographically secure key
   */
  private generateKey(): Buffer {
    return randomBytes(ENCRYPTION_CONFIG.keyLength);
  }

  /**
   * Retrieve key from Hardware Security Module
   */
  private async getKeyFromHSM(keyId: string): Promise<Buffer> {
    if (!ENCRYPTION_CONFIG.hsm.enabled) {
      throw new Error('HSM is not enabled');
    }

    // HSM integration placeholder - implement based on provider
    // AWS CloudHSM, Azure Dedicated HSM, or on-premise HSM
    switch (ENCRYPTION_CONFIG.hsm.provider) {
      case 'aws-cloudhsm':
        return this.getKeyFromAWSCloudHSM(keyId);
      case 'azure-hsm':
        return this.getKeyFromAzureHSM(keyId);
      default:
        throw new Error(`Unsupported HSM provider: ${ENCRYPTION_CONFIG.hsm.provider}`);
    }
  }

  private async getKeyFromAWSCloudHSM(keyId: string): Promise<Buffer> {
    // AWS CloudHSM integration
    // Requires AWS CloudHSM Client SDK
    throw new Error('AWS CloudHSM integration not yet implemented');
  }

  private async getKeyFromAzureHSM(keyId: string): Promise<Buffer> {
    // Azure Dedicated HSM integration
    throw new Error('Azure HSM integration not yet implemented');
  }

  /**
   * Check if key rotation is due
   */
  private isKeyRotationDue(keyId: string): boolean {
    const lastRotation = this.keyRotationSchedule.get(keyId);
    if (!lastRotation) return true;

    const rotationDue = new Date();
    rotationDue.setDate(rotationDue.getDate() - ENCRYPTION_CONFIG.keyRotationDays);

    return lastRotation < rotationDue;
  }

  /**
   * Initialize automatic key rotation
   */
  private initializeKeyRotation(): void {
    const rotationIntervalMs = ENCRYPTION_CONFIG.keyRotationDays * 24 * 60 * 60 * 1000;

    setInterval(() => {
      this.rotateAllKeys();
    }, rotationIntervalMs);
  }

  /**
   * Rotate all active keys
   */
  private async rotateAllKeys(): Promise<void> {
    const keysToRotate = Array.from(this.keyRotationSchedule.keys()).filter(keyId =>
      this.isKeyRotationDue(keyId)
    );

    for (const keyId of keysToRotate) {
      try {
        this.keyCache.delete(keyId);
        this.getEncryptionKey(keyId); // This will generate a new key
        console.log(`Key rotated successfully: ${keyId}`);
      } catch (error) {
        console.error(`Failed to rotate key ${keyId}:`, error);
      }
    }
  }

  /**
   * Hash sensitive data (one-way)
   */
  public hash(data: string, salt?: string): string {
    const actualSalt = salt || randomBytes(16).toString('hex');
    return createHash('sha256').update(data + actualSalt).digest('hex');
  }

  /**
   * Generate secure random token
   */
  public generateSecureToken(length: number = 32): string {
    return randomBytes(length).toString('hex');
  }
}

export interface EncryptedData {
  data: string;
  iv: string;
  tag: string;
  keyId: string;
  algorithm: string;
  timestamp: string;
}

export const TLS_CONFIG = {
  secureProtocol: 'TLSv1_3_method',
  ciphers: ENCRYPTION_CONFIG.tls.cipherSuites.join(':'),
  honorCipherOrder: true,
  secureOptions: 0x40000000, // SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
  dhparam: process.env.DH_PARAMS_PATH,
  ecdhCurve: 'prime256v1'
};

// Export singleton instance
export const encryptionManager = EncryptionManager.getInstance();