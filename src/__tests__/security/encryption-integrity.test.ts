import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import {
  encryptAesGcm,
  decryptAesGcm,
  setupUserMasterKeyEncryption,
  decodeUserMasterKey,
} from '../../lib/crypto';
import { decodeAndGetMasterKeyFromRefreshToken, createRefreshToken } from '../../lib/auth';

describe('security: encryption integrity', () => {
  beforeAll(() => {
    process.env.JWT_SECRET = 'test-secret-key-for-jwt-operations-32-bytes-min';
  });

  describe('master key encryption in tokens', () => {
    it('should encrypt master key in refresh token with JWT_SECRET', async () => {
      const userId = new mongoose.Types.ObjectId().toString();
      const masterKey = crypto.randomBytes(32).toString('base64');

      const token = await createRefreshToken(userId, masterKey);
      const decoded = jwt.decode(token) as any;

      // Master key should be encrypted in the token
      expect(decoded.encryptedMasterKey).toBeDefined();
      expect(decoded.encryptedMasterKey).not.toBe(masterKey);
      expect(decoded.masterKeyIv).toBeDefined();
      expect(decoded.masterKeyAuthTag).toBeDefined();
    });

    it('should allow decrypting master key from refresh token', async () => {
      const userId = new mongoose.Types.ObjectId().toString();
      const masterKey = crypto.randomBytes(32).toString('base64');

      const token = await createRefreshToken(userId, masterKey);

      const decoded = await decodeAndGetMasterKeyFromRefreshToken(token);

      expect(decoded.masterKey).toBe(masterKey);
      expect(decoded.userId).toBe(userId);
    });

    it('should fail decryption with tampered encrypted master key', async () => {
      const userId = new mongoose.Types.ObjectId().toString();
      const masterKey = crypto.randomBytes(32).toString('base64');

      const token = await createRefreshToken(userId, masterKey);
      const decoded = jwt.decode(token, { complete: true }) as any;

      // Tamper with encrypted master key
      const tamperedPayload = {
        ...decoded.payload,
        encryptedMasterKey: 'tampered',
      };
      const tamperedToken = jwt.sign(tamperedPayload, process.env.JWT_SECRET as string);

      await expect(decodeAndGetMasterKeyFromRefreshToken(tamperedToken)).rejects.toThrow();
    });

    it('should fail decryption with tampered auth tag', async () => {
      const userId = new mongoose.Types.ObjectId().toString();
      const masterKey = crypto.randomBytes(32).toString('base64');

      const token = await createRefreshToken(userId, masterKey);
      const decoded = jwt.decode(token, { complete: true }) as any;

      // Tamper with auth tag
      const tamperedPayload = {
        ...decoded.payload,
        masterKeyAuthTag: crypto.randomBytes(16).toString('base64'),
      };
      const tamperedToken = jwt.sign(tamperedPayload, process.env.JWT_SECRET as string);

      await expect(decodeAndGetMasterKeyFromRefreshToken(tamperedToken)).rejects.toThrow();
    });

    it('should fail decryption with tampered IV', async () => {
      const userId = new mongoose.Types.ObjectId().toString();
      const masterKey = crypto.randomBytes(32).toString('base64');

      const token = await createRefreshToken(userId, masterKey);
      const decoded = jwt.decode(token, { complete: true }) as any;

      // Tamper with IV
      const tamperedPayload = {
        ...decoded.payload,
        masterKeyIv: crypto.randomBytes(12).toString('base64'),
      };
      const tamperedToken = jwt.sign(tamperedPayload, process.env.JWT_SECRET as string);

      await expect(decodeAndGetMasterKeyFromRefreshToken(tamperedToken)).rejects.toThrow();
    });
  });

  describe('master key encryption in database', () => {
    it('should encrypt master key when storing in database', async () => {
      const password = 'test-password';
      const result = await setupUserMasterKeyEncryption(password);

      // Master key should not be stored in plaintext
      expect(result.encryptedMasterKey).toBeDefined();
      expect(result.encryptedMasterKey).not.toBe(result.masterKey.toString('base64'));
    });

    it('should decrypt master key with correct password', async () => {
      const password = 'correct-password';
      const setupResult = await setupUserMasterKeyEncryption(password);

      const userDocument = {
        kdfSalt: setupResult.kdfSalt.toString('base64'),
        encryptedMasterKey: setupResult.encryptedMasterKey.toString('base64'),
        masterKeyIv: setupResult.masterKeyIv.toString('base64'),
        masterKeyAuthTag: setupResult.masterKeyAuthTag.toString('base64'),
      };

      const decoded = await decodeUserMasterKey(userDocument, password);
      expect(decoded).toBe(setupResult.masterKey.toString('base64'));
    });

    it('should fail to decrypt master key with wrong password', async () => {
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

    it('should use different encryption on each setup (random IV)', async () => {
      const password = 'same-password';

      const result1 = await setupUserMasterKeyEncryption(password);
      const result2 = await setupUserMasterKeyEncryption(password);

      // Even though same password, encryption should be different due to random IV
      expect(result1.encryptedMasterKey).not.toBe(result2.encryptedMasterKey);
      expect(result1.masterKeyIv).not.toBe(result2.masterKeyIv);
    });
  });

  describe('note content encryption', () => {
    it('should encrypt note content', async () => {
      const plaintext = Buffer.from('secret note content');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);

      expect(encrypted).toBeDefined();
      expect(authTag).toBeDefined();
      expect(encrypted.toString()).not.toBe(plaintext.toString());
    });

    it('should decrypt note content correctly', async () => {
      const plaintext = Buffer.from('secret note content');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);
      const { decrypted } = await decryptAesGcm(encrypted, authTag, key, iv);

      expect(decrypted.equals(plaintext)).toBe(true);
      expect(decrypted.toString()).toBe('secret note content');
    });

    it('should fail to decrypt note with wrong key', async () => {
      const plaintext = Buffer.from('secret note content');
      const key = crypto.randomBytes(32);
      const wrongKey = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);

      await expect(decryptAesGcm(encrypted, authTag, wrongKey, iv)).rejects.toThrow();
    });

    it('should fail to decrypt note with tampered ciphertext', async () => {
      const plaintext = Buffer.from('secret note content');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);

      // Tamper with ciphertext
      const tampered = Buffer.from(encrypted);
      tampered[0] ^= 0xff;

      await expect(decryptAesGcm(tampered, authTag, key, iv)).rejects.toThrow();
    });

    it('should fail to decrypt note with wrong auth tag', async () => {
      const plaintext = Buffer.from('secret note content');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted } = await encryptAesGcm(plaintext, key, iv);
      const wrongAuthTag = crypto.randomBytes(16);

      await expect(decryptAesGcm(encrypted, wrongAuthTag, key, iv)).rejects.toThrow();
    });

    it('should produce different ciphertext for each encryption', async () => {
      const plaintext = Buffer.from('same content');
      const key = crypto.randomBytes(32);

      const { encrypted: encrypted1 } = await encryptAesGcm(plaintext, key, crypto.randomBytes(12));
      const { encrypted: encrypted2 } = await encryptAesGcm(plaintext, key, crypto.randomBytes(12));

      expect(encrypted1.equals(encrypted2)).toBe(false);
    });
  });

  describe('encryption provides confidentiality', () => {
    it('should not leak plaintext in ciphertext', async () => {
      const plaintext = Buffer.from('confidential data');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted } = await encryptAesGcm(plaintext, key, iv);

      expect(encrypted.toString()).not.toContain('confidential');
    });

    it('should use authenticated encryption (AEAD)', async () => {
      const plaintext = Buffer.from('message');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);

      // Auth tag should be present and required for decryption
      expect(authTag).toBeDefined();
      expect(authTag.length).toBe(16); // 128-bit auth tag

      // Decryption fails without correct auth tag
      await expect(decryptAesGcm(encrypted, Buffer.from('0'.repeat(32)), key, iv)).rejects.toThrow();
    });

    it('should use proper IV for each encryption', async () => {
      const plaintext = Buffer.from('same message');
      const key = crypto.randomBytes(32);

      const { encrypted: encrypted1, authTag: tag1 } = await encryptAesGcm(plaintext, key, crypto.randomBytes(12));
      const { encrypted: encrypted2, authTag: tag2 } = await encryptAesGcm(plaintext, key, crypto.randomBytes(12));

      // Different IVs should result in different ciphertexts and auth tags
      expect(encrypted1.equals(encrypted2)).toBe(false);
      expect(tag1.equals(tag2)).toBe(false);
    });
  });

  describe('encryption prevents tampering detection', () => {
    it('should detect tampering via auth tag validation', async () => {
      const plaintext = Buffer.from('sensitive data');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);

      // Tamper with encrypted data
      const tampered = Buffer.from(encrypted);
      tampered[0] ^= 0x01;

      // Decryption should fail due to auth tag mismatch
      await expect(decryptAesGcm(tampered, authTag, key, iv)).rejects.toThrow();
    });

    it('should prevent tag forgery attacks', async () => {
      const plaintext = Buffer.from('original message');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted: originalCiphertext } = await encryptAesGcm(plaintext, key, iv);

      // Attacker tries to create fake auth tag
      const fakeAuthTag = crypto.randomBytes(16);

      // This should fail
      await expect(decryptAesGcm(originalCiphertext, fakeAuthTag, key, iv)).rejects.toThrow();
    });

    it('should make single-bit changes detectable via auth tag', async () => {
      const plaintext = Buffer.from('important message');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);

      const { encrypted, authTag } = await encryptAesGcm(plaintext, key, iv);

      // Change single bit in ciphertext
      const tampered = Buffer.from(encrypted);
      tampered[Math.floor(encrypted.length / 2)] ^= 0x01;

      // Auth tag validation should catch this
      await expect(decryptAesGcm(tampered, authTag, key, iv)).rejects.toThrow();
    });
  });
});
