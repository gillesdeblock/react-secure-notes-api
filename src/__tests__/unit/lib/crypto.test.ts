import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  encryptPassword,
  verifyPassword,
  derivePasswordKey,
  setupUserMasterKeyEncryption,
  decodeUserMasterKey,
  encryptMasterKey,
  decryptMasterKey,
  encryptAesGcm,
  decryptAesGcm,
} from '../../../lib/crypto';

describe('crypto', () => {
  describe('password hashing (argon2)', () => {
    it('should hash password successfully', async () => {
      const password = 'test-password-123';
      const hash = await encryptPassword(password);

      expect(typeof hash).toBe('string');
      expect(hash.length).toBeGreaterThan(0);
    });

    it('should verify correct password', async () => {
      const password = 'correct-password';
      const hash = await encryptPassword(password);
      const isValid = await verifyPassword(hash, password);

      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'correct-password';
      const hash = await encryptPassword(password);
      const isValid = await verifyPassword(hash, 'wrong-password');

      expect(isValid).toBe(false);
    });

    it('should produce different hashes for different passwords', async () => {
      const hash1 = await encryptPassword('password1');
      const hash2 = await encryptPassword('password2');

      expect(hash1).not.toBe(hash2);
    });

    it('should produce different hashes for same password (due to random salt)', async () => {
      const password = 'same-password';
      const hash1 = await encryptPassword(password);
      const hash2 = await encryptPassword(password);

      expect(hash1).not.toBe(hash2);
      expect(await verifyPassword(hash1, password)).toBe(true);
      expect(await verifyPassword(hash2, password)).toBe(true);
    });
  });

  describe('master key derivation', () => {
    it('should derive key from password and salt', async () => {
      const password = 'test-password';
      const salt = crypto.randomBytes(12);
      const key = await derivePasswordKey(password, salt);

      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32);
    });

    it('should produce same key for same password and salt', async () => {
      const password = 'test-password';
      const salt = crypto.randomBytes(12);

      const key1 = await derivePasswordKey(password, salt);
      const key2 = await derivePasswordKey(password, salt);

      expect(key1.equals(key2)).toBe(true);
    });

    it('should produce different key for different salt', async () => {
      const password = 'test-password';
      const salt1 = crypto.randomBytes(12);
      const salt2 = crypto.randomBytes(12);

      const key1 = await derivePasswordKey(password, salt1);
      const key2 = await derivePasswordKey(password, salt2);

      expect(key1.equals(key2)).toBe(false);
    });

    it('should produce different key for different password', async () => {
      const salt = crypto.randomBytes(12);

      const key1 = await derivePasswordKey('password1', salt);
      const key2 = await derivePasswordKey('password2', salt);

      expect(key1.equals(key2)).toBe(false);
    });

    it('should produce key with correct length (32 bytes)', async () => {
      const password = 'test-password';
      const salt = crypto.randomBytes(12);
      const key = await derivePasswordKey(password, salt);

      expect(key.length).toBe(32);
    });
  });

  describe('AES-GCM encryption/decryption', () => {
    it('should encrypt plaintext to ciphertext', async () => {
      const plaintext = Buffer.from('secret message');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);

      expect(Buffer.isBuffer(encrypted)).toBe(true);
      expect(Buffer.isBuffer(authTag)).toBe(true);
      expect(encrypted.length).toBeGreaterThan(0);
    });

    it('should decrypt ciphertext back to plaintext', async () => {
      const plaintext = Buffer.from('secret message');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);
      const { decrypted } = await decryptAesGcm(encrypted, authTag, key, iv);

      expect(decrypted.equals(plaintext)).toBe(true);
      expect(decrypted.toString()).toBe('secret message');
    });

    it('should fail to decrypt with wrong key', async () => {
      const plaintext = Buffer.from('secret message');
      const key = crypto.randomBytes(32);
      const wrongKey = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);

      await expect(decryptAesGcm(encrypted, authTag, wrongKey, iv)).rejects.toThrow();
    });

    it('should fail to decrypt with tampered ciphertext', async () => {
      const plaintext = Buffer.from('secret message');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);
      const tampered = Buffer.from(encrypted);
      tampered[0] ^= 0xff; // flip bits in first byte

      await expect(decryptAesGcm(tampered, authTag, key, iv)).rejects.toThrow();
    });

    it('should fail to decrypt with wrong auth tag', async () => {
      const plaintext = Buffer.from('secret message');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted } = await encryptAesGcm(plaintext, key, iv);
      const wrongAuthTag = crypto.randomBytes(16);

      await expect(decryptAesGcm(encrypted, wrongAuthTag, key, iv)).rejects.toThrow();
    });

    it('should produce different ciphertext for each encryption (different IV)', async () => {
      const plaintext = Buffer.from('secret message');
      const key = crypto.randomBytes(32);

      const { encrypted: encrypted1 } = await encryptAesGcm(plaintext, key, crypto.randomBytes(12));
      const { encrypted: encrypted2 } = await encryptAesGcm(plaintext, key, crypto.randomBytes(12));

      expect(encrypted1.equals(encrypted2)).toBe(false);
    });

    it('should handle empty plaintext', async () => {
      const plaintext = Buffer.from('');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);
      const { decrypted } = await decryptAesGcm(encrypted, authTag, key, iv);

      expect(decrypted.equals(plaintext)).toBe(true);
      expect(decrypted.length).toBe(0);
    });

    it('should handle large plaintext', async () => {
      const plaintext = Buffer.alloc(10000, 'secret message');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);
      const { decrypted } = await decryptAesGcm(encrypted, authTag, key, iv);

      expect(decrypted.equals(plaintext)).toBe(true);
      expect(decrypted.length).toBe(10000);
    });
  });

  describe('master key encryption/decryption', () => {
    it('should encrypt and decrypt master key', async () => {
      const masterKey = crypto.randomBytes(32);
      const password = crypto.randomBytes(32);

      const { encryptedMasterKey, masterKeyIv, masterKeyAuthTag } = await encryptMasterKey(
        masterKey,
        password,
      );
      const decrypted = await decryptMasterKey(encryptedMasterKey, password, masterKeyAuthTag, masterKeyIv);

      expect(decrypted.equals(masterKey)).toBe(true);
    });

    it('should fail to decrypt with wrong password', async () => {
      const masterKey = crypto.randomBytes(32);
      const password = crypto.randomBytes(32);
      const wrongPassword = crypto.randomBytes(32);

      const { encryptedMasterKey, masterKeyIv, masterKeyAuthTag } = await encryptMasterKey(
        masterKey,
        password,
      );

      await expect(decryptMasterKey(encryptedMasterKey, wrongPassword, masterKeyAuthTag, masterKeyIv)).rejects.toThrow();
    });

    it('should produce different encrypted output for same key', async () => {
      const masterKey = crypto.randomBytes(32);
      const password = crypto.randomBytes(32);

      const result1 = await encryptMasterKey(masterKey, password);
      const result2 = await encryptMasterKey(masterKey, password);

      expect(result1.encryptedMasterKey.equals(result2.encryptedMasterKey)).toBe(false);
      expect(result1.masterKeyIv.equals(result2.masterKeyIv)).toBe(false);
    });
  });

  describe('setup user master key encryption', () => {
    it('should generate master key and encryption properties', async () => {
      const password = 'test-password';
      const result = await setupUserMasterKeyEncryption(password);

      expect(Buffer.isBuffer(result.kdfSalt)).toBe(true);
      expect(Buffer.isBuffer(result.masterKey)).toBe(true);
      expect(Buffer.isBuffer(result.encryptedMasterKey)).toBe(true);
      expect(Buffer.isBuffer(result.masterKeyIv)).toBe(true);
      expect(Buffer.isBuffer(result.masterKeyAuthTag)).toBe(true);
    });

    it('should generate unique master key each time', async () => {
      const password = 'test-password';
      const result1 = await setupUserMasterKeyEncryption(password);
      const result2 = await setupUserMasterKeyEncryption(password);

      expect(result1.masterKey.equals(result2.masterKey)).toBe(false);
    });

    it('should generate unique salt each time', async () => {
      const password = 'test-password';
      const result1 = await setupUserMasterKeyEncryption(password);
      const result2 = await setupUserMasterKeyEncryption(password);

      expect(result1.kdfSalt.equals(result2.kdfSalt)).toBe(false);
    });

    it('should allow decoding master key with correct password', async () => {
      const password = 'test-password';
      const setupResult = await setupUserMasterKeyEncryption(password);

      const userDocument = {
        kdfSalt: setupResult.kdfSalt.toString('base64'),
        encryptedMasterKey: setupResult.encryptedMasterKey.toString('base64'),
        masterKeyIv: setupResult.masterKeyIv.toString('base64'),
        masterKeyAuthTag: setupResult.masterKeyAuthTag.toString('base64'),
      };

      const decoded = await decodeUserMasterKey(userDocument, password);
      const expected = setupResult.masterKey.toString('base64');

      expect(decoded).toBe(expected);
    });

    it('should fail to decode master key with wrong password', async () => {
      const password = 'correct-password';
      const setupResult = await setupUserMasterKeyEncryption(password);

      const userDocument = {
        kdfSalt: setupResult.kdfSalt.toString('base64'),
        encryptedMasterKey: setupResult.encryptedMasterKey.toString('base64'),
        masterKeyIv: setupResult.masterKeyIv.toString('base64'),
        masterKeyAuthTag: setupResult.masterKeyAuthTag.toString('base64'),
      };

      await expect(decodeUserMasterKey(userDocument, 'wrong-password')).rejects.toThrow();
    });

    it('should fail to decode when user document missing required properties', async () => {
      const userDocument = { kdfSalt: 'invalid' };

      await expect(decodeUserMasterKey(userDocument, 'password')).rejects.toThrow('unable to decode master key');
    });
  });
});
