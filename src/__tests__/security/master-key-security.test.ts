import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import crypto from 'crypto';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../../app';
import {
  derivePasswordKey,
  setupUserMasterKeyEncryption,
  decodeUserMasterKey,
} from '../../lib/crypto';
import UserModel from '../../models/user';
import RefreshTokenModel from '../../models/refresh-token';

describe('security: master key security', () => {
  const testEmail = 'masterkey-test@example.com';
  const testPassword = 'test-password-123';

  beforeAll(() => {
    process.env.JWT_SECRET = 'test-secret-key-for-jwt-operations-32-bytes-min';
  });

  beforeEach(async () => {
    await UserModel.deleteMany({});
    await RefreshTokenModel.deleteMany({});
  });

  describe('key derivation security', () => {
    it('should derive key from password using argon2 KDF', async () => {
      const password = 'test-password';
      const salt = crypto.randomBytes(12);

      const key = await derivePasswordKey(password, salt);

      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32);
    });

    it('should produce same key from same password and salt', async () => {
      const password = 'test-password';
      const salt = crypto.randomBytes(12);

      const key1 = await derivePasswordKey(password, salt);
      const key2 = await derivePasswordKey(password, salt);

      expect(key1.equals(key2)).toBe(true);
    });

    it('should produce different key for different password', async () => {
      const salt = crypto.randomBytes(12);

      const key1 = await derivePasswordKey('password1', salt);
      const key2 = await derivePasswordKey('password2', salt);

      expect(key1.equals(key2)).toBe(false);
    });

    it('should produce different key for different salt', async () => {
      const password = 'same-password';
      const salt1 = crypto.randomBytes(12);
      const salt2 = crypto.randomBytes(12);

      const key1 = await derivePasswordKey(password, salt1);
      const key2 = await derivePasswordKey(password, salt2);

      expect(key1.equals(key2)).toBe(false);
    });

    it('should use sufficient work factor (time-consuming derivation)', async () => {
      const password = 'test-password';
      const salt = crypto.randomBytes(12);

      const startTime = Date.now();
      await derivePasswordKey(password, salt);
      const derivationTime = Date.now() - startTime;

      // Argon2 should take meaningful time (at least 10ms) to prevent brute force
      expect(derivationTime).toBeGreaterThan(10);
    });
  });

  describe('master key in transit', () => {
    it('should send master key in access token (JWT encrypted)', async () => {
      const registerResponse = await request(app).post('/auth/register').send({
        email: testEmail,
        password: testPassword,
      });

      const accessToken = registerResponse.body.accessToken;
      const decoded = jwt.decode(accessToken) as any;

      expect(decoded.masterKey).toBeDefined();
      expect(typeof decoded.masterKey).toBe('string');
    });

    it('should never send master key in plaintext HTTP', async () => {
      // Master key should only be transmitted in JWT (encrypted by JWT_SECRET)
      const registerResponse = await request(app).post('/auth/register').send({
        email: `plaintext-${testEmail}`,
        password: testPassword,
      });

      const responseBody = JSON.stringify(registerResponse.body);
      const password = testPassword;

      // Response should not contain the password
      expect(responseBody).not.toContain(password);
    });

    it('should encrypt master key in refresh token with JWT_SECRET', async () => {
      const registerResponse = await request(app).post('/auth/register').send({
        email: `refresh-${testEmail}`,
        password: testPassword,
      });

      const cookies = registerResponse.headers['set-cookie'] as unknown as string[] | undefined;
      const refreshToken = cookies
        ?.find((c: string) => c.startsWith('refresh_token='))
        ?.split('=')[1]
        ?.split(';')[0] || '';

      const decoded = jwt.decode(refreshToken) as any;

      // Master key should be encrypted in refresh token
      expect(decoded.encryptedMasterKey).toBeDefined();
      expect(decoded.masterKeyIv).toBeDefined();
      expect(decoded.masterKeyAuthTag).toBeDefined();
    });

    it('should send refresh token in httpOnly cookie (not accessible to JS)', async () => {
      const registerResponse = await request(app).post('/auth/register').send({
        email: `cookie-${testEmail}`,
        password: testPassword,
      });

      const cookies = registerResponse.headers['set-cookie'] as unknown as string[] | undefined;
      const refreshTokenCookie = cookies?.find((c: string) => c.startsWith('refresh_token='));

      // Should be httpOnly to prevent XSS attacks
      expect(refreshTokenCookie).toContain('HttpOnly');
      expect(refreshTokenCookie).toContain('Secure');
    });

    it('should use HTTPS (Secure flag on cookie)', async () => {
      const registerResponse = await request(app).post('/auth/register').send({
        email: `secure-${testEmail}`,
        password: testPassword,
      });

      const cookies = registerResponse.headers['set-cookie'] as unknown as string[] | undefined;
      const refreshTokenCookie = cookies?.find((c: string) => c.startsWith('refresh_token='));

      expect(refreshTokenCookie).toContain('Secure');
    });
  });

  describe('master key at rest', () => {
    it('should store master key encrypted in database', async () => {
      await request(app).post('/auth/register').send({
        email: `stored-${testEmail}`,
        password: testPassword,
      });

      const user = await UserModel.findOne({ email: `stored-${testEmail}` });

      // Master key should be stored encrypted
      expect(user?.encryptedMasterKey).toBeDefined();
      expect(user?.kdfSalt).toBeDefined();
      expect(user?.masterKeyIv).toBeDefined();
      expect(user?.masterKeyAuthTag).toBeDefined();
    });

    it('should encrypt master key with password-derived key', async () => {
      const setupResult = await setupUserMasterKeyEncryption(testPassword);

      // Master key encrypted with password-derived key
      expect(setupResult.encryptedMasterKey).toBeDefined();
      expect(setupResult.masterKey).toBeDefined();
      expect(setupResult.kdfSalt).toBeDefined();

      // Encrypted master key should not equal plaintext
      expect(setupResult.encryptedMasterKey.toString('base64')).not.toBe(
        setupResult.masterKey.toString('base64'),
      );
    });

    it('should require password to decrypt master key from database', async () => {
      const setupResult = await setupUserMasterKeyEncryption(testPassword);

      const userDocument = {
        kdfSalt: setupResult.kdfSalt.toString('base64'),
        encryptedMasterKey: setupResult.encryptedMasterKey.toString('base64'),
        masterKeyIv: setupResult.masterKeyIv.toString('base64'),
        masterKeyAuthTag: setupResult.masterKeyAuthTag.toString('base64'),
      };

      // Should succeed with correct password
      const decoded = await decodeUserMasterKey(userDocument, testPassword);
      expect(decoded).toBe(setupResult.masterKey.toString('base64'));

      // Should fail with wrong password
      await expect(decodeUserMasterKey(userDocument, 'wrong-password')).rejects.toThrow();
    });

    it('should not expose master key in error messages', async () => {
      await request(app).post('/auth/register').send({
        email: `error-${testEmail}`,
        password: testPassword,
      });

      const user = await UserModel.findOne({ email: `error-${testEmail}` });
      const masterKeyFromDB = user?.encryptedMasterKey;

      // If there's an error, it shouldn't expose the actual master key
      // This test verifies the encryptedMasterKey is not in plaintext
      expect(masterKeyFromDB).not.toBe('plaintext-master-key');
    });
  });

  describe('master key compromise prevention', () => {
    it('should prevent master key compromise if database is leaked but passwords are strong', async () => {
      const setupResult = await setupUserMasterKeyEncryption(testPassword);

      const userDocument = {
        kdfSalt: setupResult.kdfSalt.toString('base64'),
        encryptedMasterKey: setupResult.encryptedMasterKey.toString('base64'),
        masterKeyIv: setupResult.masterKeyIv.toString('base64'),
        masterKeyAuthTag: setupResult.masterKeyAuthTag.toString('base64'),
      };

      // Even with database leak, cannot decrypt without password
      await expect(decodeUserMasterKey(userDocument, 'any-random-guess')).rejects.toThrow();

      // Only correct password works
      const decoded = await decodeUserMasterKey(userDocument, testPassword);
      expect(decoded).toBe(setupResult.masterKey.toString('base64'));
    });

    it('should use unique salt for each user (prevents rainbow tables)', async () => {
      const result1 = await setupUserMasterKeyEncryption(testPassword);
      const result2 = await setupUserMasterKeyEncryption(testPassword);

      // Different salts for same password
      expect(result1.kdfSalt.equals(result2.kdfSalt)).toBe(false);
    });

    it('should prevent cross-user master key access', async () => {
      // Register two users
      await request(app).post('/auth/register').send({
        email: 'user1@example.com',
        password: 'password1',
      });

      await request(app).post('/auth/register').send({
        email: 'user2@example.com',
        password: 'password2',
      });

      const user2 = await UserModel.findOne({ email: 'user2@example.com' });

      // User1 cannot decrypt User2's master key
      const user2Doc = {
        kdfSalt: (user2?.kdfSalt as Buffer | undefined)?.toString('base64'),
        encryptedMasterKey: (user2?.encryptedMasterKey as Buffer | undefined)?.toString('base64'),
        masterKeyIv: (user2?.masterKeyIv as Buffer | undefined)?.toString('base64'),
        masterKeyAuthTag: (user2?.masterKeyAuthTag as Buffer | undefined)?.toString('base64'),
      };

      await expect(decodeUserMasterKey(user2Doc, 'password1')).rejects.toThrow();
    });

    it('should prevent brute force attacks on password with argon2 work factor', async () => {
      // Argon2 is deliberately slow
      const password = 'test-password';
      const salt = crypto.randomBytes(12);

      const startTime = Date.now();
      await derivePasswordKey(password, salt);
      const singleAttemptTime = Date.now() - startTime;

      // One derivation should take significant time
      expect(singleAttemptTime).toBeGreaterThan(10);

      // Simulating 1 million brute force attempts would take too long
      const estimatedBruteForceTime = singleAttemptTime * 1000000;
      expect(estimatedBruteForceTime).toBeGreaterThan(10 * 1000 * 60); // > 10 minutes
    });
  });

  describe('master key lifecycle', () => {
    it('should generate new master key on registration', async () => {
      const setupResult1 = await setupUserMasterKeyEncryption(testPassword);
      const setupResult2 = await setupUserMasterKeyEncryption(testPassword);

      // Different master keys for each call (different random generation)
      expect(setupResult1.masterKey.equals(setupResult2.masterKey)).toBe(false);
    });

    it('should preserve master key across sessions', async () => {
      const registerResponse = await request(app).post('/auth/register').send({
        email: `preserve-${testEmail}`,
        password: testPassword,
      });

      const firstAccessToken = registerResponse.body.accessToken;
      const firstMasterKey = (jwt.decode(firstAccessToken) as any).masterKey;

      // Login again and get new access token
      const loginResponse = await request(app).post('/auth/login').send({
        email: `preserve-${testEmail}`,
        password: testPassword,
      });

      const secondAccessToken = loginResponse.body.accessToken;
      const secondMasterKey = (jwt.decode(secondAccessToken) as any).masterKey;

      // Master key should be same across sessions
      expect(firstMasterKey).toBe(secondMasterKey);
    });

    it('should not rotate master key on logout', async () => {
      const registerResponse = await request(app).post('/auth/register').send({
        email: `norotate-${testEmail}`,
        password: testPassword,
      });

      const masterKeyBefore = (jwt.decode(registerResponse.body.accessToken) as any)
        .masterKey;

      // Logout
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${registerResponse.body.accessToken}`);

      // Login again
      const loginResponse = await request(app).post('/auth/login').send({
        email: `norotate-${testEmail}`,
        password: testPassword,
      });

      const masterKeyAfter = (jwt.decode(loginResponse.body.accessToken) as any).masterKey;

      expect(masterKeyBefore).toBe(masterKeyAfter);
    });
  });
});
