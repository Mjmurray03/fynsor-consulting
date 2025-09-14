/**
 * Multi-Factor Authentication (MFA) using TOTP
 * Time-based One-Time Password implementation for Fynsor Consulting
 */

import crypto from 'crypto';
import { z } from 'zod';
import { createClient } from '@supabase/supabase-js';

// TOTP Configuration
const TOTP_CONFIG = {
  secretLength: 32,
  window: 1, // Allow 1 time step before/after current
  step: 30, // 30 second time steps
  digits: 6, // 6 digit codes
  algorithm: 'SHA1' as const,
  issuer: 'Fynsor Consulting',
};

// MFA schemas
const MFASecretSchema = z.object({
  userId: z.string(),
  secret: z.string(),
  backupCodes: z.array(z.string()),
  enabled: z.boolean(),
  createdAt: z.date(),
  lastUsed: z.date().optional(),
});

const MFAVerificationSchema = z.object({
  userId: z.string(),
  code: z.string().length(6),
  timestamp: z.date(),
  ipAddress: z.string().ip(),
  userAgent: z.string(),
});

export type MFASecret = z.infer<typeof MFASecretSchema>;
export type MFAVerification = z.infer<typeof MFAVerificationSchema>;

// Base32 encoding/decoding for TOTP secrets
class Base32 {
  private static readonly ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  static encode(buffer: Buffer): string {
    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < buffer.length; i++) {
      value = (value << 8) | buffer[i];
      bits += 8;

      while (bits >= 5) {
        output += this.ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      output += this.ALPHABET[(value << (5 - bits)) & 31];
    }

    return output;
  }

  static decode(str: string): Buffer {
    const cleanStr = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
    let bits = 0;
    let value = 0;
    const output: number[] = [];

    for (let i = 0; i < cleanStr.length; i++) {
      const idx = this.ALPHABET.indexOf(cleanStr[i]);
      if (idx === -1) {
        throw new Error('Invalid base32 character');
      }

      value = (value << 5) | idx;
      bits += 5;

      if (bits >= 8) {
        output.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }

    return Buffer.from(output);
  }
}

// TOTP Implementation
export class TOTPService {
  private supabase: ReturnType<typeof createClient>;

  constructor() {
    this.supabase = createClient(
      process.env.SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_KEY!
    );
  }

  // Generate TOTP secret
  generateSecret(): string {
    const buffer = crypto.randomBytes(TOTP_CONFIG.secretLength);
    return Base32.encode(buffer);
  }

  // Generate backup codes
  generateBackupCodes(count: number = 10): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
      // Generate 8-character alphanumeric codes
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      codes.push(code);
    }
    return codes;
  }

  // Generate TOTP code for given secret and time
  generateTOTP(secret: string, time?: number): string {
    const timestamp = Math.floor((time || Date.now()) / 1000);
    const timeStep = Math.floor(timestamp / TOTP_CONFIG.step);

    const secretBuffer = Base32.decode(secret);
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeUInt32BE(Math.floor(timeStep / 0x100000000), 0);
    timeBuffer.writeUInt32BE(timeStep & 0xffffffff, 4);

    const hmac = crypto.createHmac(TOTP_CONFIG.algorithm.toLowerCase(), secretBuffer);
    hmac.update(timeBuffer);
    const digest = hmac.digest();

    const offset = digest[digest.length - 1] & 0x0f;
    const code = (
      ((digest[offset] & 0x7f) << 24) |
      ((digest[offset + 1] & 0xff) << 16) |
      ((digest[offset + 2] & 0xff) << 8) |
      (digest[offset + 3] & 0xff)
    ) % Math.pow(10, TOTP_CONFIG.digits);

    return code.toString().padStart(TOTP_CONFIG.digits, '0');
  }

  // Verify TOTP code
  verifyTOTP(secret: string, code: string, time?: number): boolean {
    const timestamp = time || Date.now();
    const currentWindow = Math.floor(timestamp / 1000 / TOTP_CONFIG.step);

    // Check current window and adjacent windows
    for (let i = -TOTP_CONFIG.window; i <= TOTP_CONFIG.window; i++) {
      const windowTime = (currentWindow + i) * TOTP_CONFIG.step * 1000;
      const expectedCode = this.generateTOTP(secret, windowTime);

      if (this.constantTimeEquals(code, expectedCode)) {
        return true;
      }
    }

    return false;
  }

  // Generate QR code data for TOTP setup
  generateQRCodeData(secret: string, userEmail: string): string {
    const encodedIssuer = encodeURIComponent(TOTP_CONFIG.issuer);
    const encodedUser = encodeURIComponent(userEmail);
    const encodedSecret = secret;

    return `otpauth://totp/${encodedIssuer}:${encodedUser}?secret=${encodedSecret}&issuer=${encodedIssuer}&algorithm=${TOTP_CONFIG.algorithm}&digits=${TOTP_CONFIG.digits}&period=${TOTP_CONFIG.step}`;
  }

  // Setup MFA for user
  async setupMFA(userId: string, userEmail: string): Promise<{
    secret: string;
    qrCodeData: string;
    backupCodes: string[];
  }> {
    const secret = this.generateSecret();
    const backupCodes = this.generateBackupCodes();
    const qrCodeData = this.generateQRCodeData(secret, userEmail);

    // Store in database (not yet enabled)
    await this.supabase
      .from('mfa_secrets')
      .upsert({
        user_id: userId,
        secret: this.encryptSecret(secret),
        backup_codes: this.encryptBackupCodes(backupCodes),
        enabled: false,
        created_at: new Date().toISOString(),
      });

    return {
      secret,
      qrCodeData,
      backupCodes,
    };
  }

  // Enable MFA after verification
  async enableMFA(userId: string, verificationCode: string): Promise<boolean> {
    const { data: mfaData } = await this.supabase
      .from('mfa_secrets')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (!mfaData) {
      throw new Error('MFA setup not found');
    }

    const secret = this.decryptSecret(mfaData.secret);

    if (!this.verifyTOTP(secret, verificationCode)) {
      return false;
    }

    // Enable MFA
    await this.supabase
      .from('mfa_secrets')
      .update({
        enabled: true,
        last_used: new Date().toISOString(),
      })
      .eq('user_id', userId);

    // Update user record
    await this.supabase
      .from('users')
      .update({
        mfa_enabled: true,
      })
      .eq('id', userId);

    return true;
  }

  // Verify MFA code
  async verifyMFA(
    userId: string,
    code: string,
    ipAddress: string,
    userAgent: string
  ): Promise<boolean> {
    const { data: mfaData } = await this.supabase
      .from('mfa_secrets')
      .select('*')
      .eq('user_id', userId)
      .eq('enabled', true)
      .single();

    if (!mfaData) {
      return false;
    }

    const secret = this.decryptSecret(mfaData.secret);
    const backupCodes = this.decryptBackupCodes(mfaData.backup_codes);

    // Check if it's a backup code
    if (backupCodes.includes(code.toUpperCase())) {
      // Remove used backup code
      const updatedBackupCodes = backupCodes.filter(bc => bc !== code.toUpperCase());

      await this.supabase
        .from('mfa_secrets')
        .update({
          backup_codes: this.encryptBackupCodes(updatedBackupCodes),
          last_used: new Date().toISOString(),
        })
        .eq('user_id', userId);

      // Log backup code usage
      await this.logMFAVerification(userId, 'backup_code', ipAddress, userAgent);

      return true;
    }

    // Check TOTP code
    if (this.verifyTOTP(secret, code)) {
      await this.supabase
        .from('mfa_secrets')
        .update({
          last_used: new Date().toISOString(),
        })
        .eq('user_id', userId);

      // Log TOTP verification
      await this.logMFAVerification(userId, 'totp', ipAddress, userAgent);

      return true;
    }

    // Log failed attempt
    await this.logMFAVerification(userId, 'failed', ipAddress, userAgent);

    return false;
  }

  // Disable MFA
  async disableMFA(userId: string, verificationCode: string): Promise<boolean> {
    const isValid = await this.verifyMFA(userId, verificationCode, 'system', 'mfa-disable');

    if (!isValid) {
      return false;
    }

    // Disable MFA
    await this.supabase
      .from('mfa_secrets')
      .update({
        enabled: false,
      })
      .eq('user_id', userId);

    // Update user record
    await this.supabase
      .from('users')
      .update({
        mfa_enabled: false,
        mfa_verified: false,
      })
      .eq('id', userId);

    return true;
  }

  // Get remaining backup codes
  async getBackupCodesCount(userId: string): Promise<number> {
    const { data: mfaData } = await this.supabase
      .from('mfa_secrets')
      .select('backup_codes')
      .eq('user_id', userId)
      .eq('enabled', true)
      .single();

    if (!mfaData) {
      return 0;
    }

    const backupCodes = this.decryptBackupCodes(mfaData.backup_codes);
    return backupCodes.length;
  }

  // Regenerate backup codes
  async regenerateBackupCodes(userId: string, verificationCode: string): Promise<string[] | null> {
    const isValid = await this.verifyMFA(userId, verificationCode, 'system', 'backup-regen');

    if (!isValid) {
      return null;
    }

    const newBackupCodes = this.generateBackupCodes();

    await this.supabase
      .from('mfa_secrets')
      .update({
        backup_codes: this.encryptBackupCodes(newBackupCodes),
      })
      .eq('user_id', userId);

    return newBackupCodes;
  }

  // Check if user has MFA enabled
  async isMFAEnabled(userId: string): Promise<boolean> {
    const { data: mfaData } = await this.supabase
      .from('mfa_secrets')
      .select('enabled')
      .eq('user_id', userId)
      .single();

    return mfaData?.enabled || false;
  }

  // Log MFA verification attempts
  private async logMFAVerification(
    userId: string,
    type: 'totp' | 'backup_code' | 'failed',
    ipAddress: string,
    userAgent: string
  ): Promise<void> {
    await this.supabase
      .from('mfa_verifications')
      .insert({
        user_id: userId,
        verification_type: type,
        ip_address: ipAddress,
        user_agent: userAgent,
        timestamp: new Date().toISOString(),
        success: type !== 'failed',
      });
  }

  // Constant time string comparison to prevent timing attacks
  private constantTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }

  // Encrypt secret for storage
  private encryptSecret(secret: string): string {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(process.env.MFA_ENCRYPTION_KEY || 'default-key', 'salt', 32);
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipher(algorithm, key);
    let encrypted = cipher.update(secret, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return `${iv.toString('hex')}:${encrypted}`;
  }

  // Decrypt secret from storage
  private decryptSecret(encryptedSecret: string): string {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(process.env.MFA_ENCRYPTION_KEY || 'default-key', 'salt', 32);
    const [ivHex, encrypted] = encryptedSecret.split(':');
    const iv = Buffer.from(ivHex, 'hex');

    const decipher = crypto.createDecipher(algorithm, key);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  // Encrypt backup codes for storage
  private encryptBackupCodes(codes: string[]): string {
    return this.encryptSecret(JSON.stringify(codes));
  }

  // Decrypt backup codes from storage
  private decryptBackupCodes(encryptedCodes: string): string[] {
    const decrypted = this.decryptSecret(encryptedCodes);
    return JSON.parse(decrypted);
  }
}

// MFA Middleware
export class MFAMiddleware {
  private totpService: TOTPService;

  constructor() {
    this.totpService = new TOTPService();
  }

  // Require MFA verification for sensitive operations
  async requireMFAVerification(
    userId: string,
    code: string,
    ipAddress: string,
    userAgent: string
  ): Promise<boolean> {
    const isEnabled = await this.totpService.isMFAEnabled(userId);

    if (!isEnabled) {
      throw new Error('MFA not enabled for user');
    }

    return await this.totpService.verifyMFA(userId, code, ipAddress, userAgent);
  }

  // Check if MFA setup is required
  async isMFASetupRequired(userId: string): Promise<boolean> {
    const isEnabled = await this.totpService.isMFAEnabled(userId);
    return !isEnabled && process.env.MFA_REQUIRED === 'true';
  }
}

// Export singleton
export const totpService = new TOTPService();
export const mfaMiddleware = new MFAMiddleware();