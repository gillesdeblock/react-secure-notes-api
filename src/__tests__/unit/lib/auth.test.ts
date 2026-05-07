import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import {
  createAccessToken,
  decodeAccessToken,
  assertAccessTokenPayload,
  createRefreshToken,
  decodeAndGetMasterKeyFromRefreshToken,
  revokeActiveRefreshTokens,
} from '../../../lib/auth';
import RefreshTokenModel from '../../../models/refresh-token';

vi.mock('../../../models/refresh-token');

describe('auth', () => {
  beforeAll(() => {
    process.env.JWT_SECRET = 'test-secret-key-for-jwt-operations-32-bytes-min';
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('access token creation', () => {
    it('should create valid JWT with userId and masterKey', () => {
      const payload = { userId: '123', masterKey: 'base64encodedkey' };
      const token = createAccessToken(payload);

      expect(typeof token).toBe('string');
      expect(token.split('.').length).toBe(3); // JWT has 3 parts
    });

    it('should create token with correct default expiration (900s)', () => {
      const payload = { userId: '123', masterKey: 'base64encodedkey' };
      const token = createAccessToken(payload);
      const decoded = jwt.decode(token, { complete: true }) as any;

      expect(decoded?.payload.exp).toBeDefined();
      expect(decoded?.payload.iat).toBeDefined();
      const expiresIn = (decoded?.payload.exp as number) - (decoded?.payload.iat as number);
      expect(expiresIn).toBe(900);
    });

    it('should create token with custom expiration', () => {
      const payload = { userId: '123', masterKey: 'base64encodedkey' };
      const customExpiresIn = 3600;
      const token = createAccessToken(payload, customExpiresIn);
      const decoded = jwt.decode(token, { complete: true }) as any;

      const expiresIn = (decoded?.payload.exp as number) - (decoded?.payload.iat as number);
      expect(expiresIn).toBe(customExpiresIn);
    });

    it('should include userId in payload', () => {
      const userId = '456';
      const payload = { userId, masterKey: 'base64encodedkey' };
      const token = createAccessToken(payload);
      const decoded = jwt.decode(token) as any;

      expect(decoded.userId).toBe(userId);
    });

    it('should include masterKey in payload', () => {
      const masterKey = 'base64encodedmasterkey123';
      const payload = { userId: '123', masterKey };
      const token = createAccessToken(payload);
      const decoded = jwt.decode(token) as any;

      expect(decoded.masterKey).toBe(masterKey);
    });
  });

  describe('access token decoding', () => {
    it('should decode valid token successfully', () => {
      const payload = { userId: '123', masterKey: 'base64encodedkey' };
      const token = createAccessToken(payload);
      const decoded = decodeAccessToken(token);

      expect(decoded.userId).toBe(payload.userId);
      expect(decoded.masterKey).toBe(payload.masterKey);
    });

    it('should throw error for expired token', () => {
      const payload = { userId: '123', masterKey: 'base64encodedkey' };
      const token = createAccessToken(payload, -1); // negative expiration = already expired

      expect(() => decodeAccessToken(token)).toThrow();
    });

    it('should throw error for token with invalid signature', () => {
      const payload = { userId: '123', masterKey: 'base64encodedkey' };
      const token = createAccessToken(payload);
      const tampered = token.slice(0, -5) + 'xxxxx'; // tamper with signature

      expect(() => decodeAccessToken(tampered)).toThrow();
    });

    it('should throw error for malformed token', () => {
      const malformedToken = 'not.a.valid.token';

      expect(() => decodeAccessToken(malformedToken)).toThrow();
    });

    it('should throw error for token missing required properties', () => {
      // Create token without masterKey
      const token = jwt.sign({ userId: '123' }, process.env.JWT_SECRET as string);

      expect(() => decodeAccessToken(token)).toThrow('Access token payload is invalid!');
    });
  });

  describe('access token payload assertion', () => {
    it('should accept valid payload with userId and masterKey', () => {
      const validPayload = { userId: '123', masterKey: 'key' };

      expect(() => assertAccessTokenPayload(validPayload)).not.toThrow();
    });

    it('should reject payload without userId', () => {
      const invalidPayload = { masterKey: 'key' };

      expect(() => assertAccessTokenPayload(invalidPayload)).toThrow('Access token payload is invalid!');
    });

    it('should reject payload without masterKey', () => {
      const invalidPayload = { userId: '123' };

      expect(() => assertAccessTokenPayload(invalidPayload)).toThrow('Access token payload is invalid!');
    });

    it('should reject null payload', () => {
      expect(() => assertAccessTokenPayload(null as any)).toThrow('Access token payload is invalid!');
    });

    it('should reject string payload', () => {
      expect(() => assertAccessTokenPayload('invalid')).toThrow('Access token payload is invalid!');
    });
  });

  describe('refresh token creation', () => {
    it('should create refresh token JWT', async () => {
      const userId = '123';
      const masterKey = 'base64encodedmasterkey';

      vi.mocked(RefreshTokenModel.create).mockResolvedValue({ _id: 'tokenid' } as any);

      const token = await createRefreshToken(userId, masterKey);

      expect(typeof token).toBe('string');
      expect(token.split('.').length).toBe(3); // JWT has 3 parts
    });

    it('should store refresh token hash in database', async () => {
      const userId = '123';
      const masterKey = 'base64encodedmasterkey';

      vi.mocked(RefreshTokenModel.create).mockResolvedValue({ _id: 'tokenid' } as any);

      await createRefreshToken(userId, masterKey);

      expect(RefreshTokenModel.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId,
          hash: expect.any(String),
          expiresAt: expect.any(Date),
        }),
      );
    });

    it('should set expiration to 7 days from now', async () => {
      const userId = '123';
      const masterKey = 'base64encodedmasterkey';
      const now = Date.now();

      vi.mocked(RefreshTokenModel.create).mockResolvedValue({ _id: 'tokenid' } as any);

      await createRefreshToken(userId, masterKey, now);

      const call = vi.mocked(RefreshTokenModel.create).mock.calls[0][0];
      const expiresAt = (call as any).expiresAt.getTime();
      const expectedExpiry = now + (1000 * 60 * 60 * 24 * 7);

      expect(Math.abs(expiresAt - expectedExpiry)).toBeLessThan(100); // within 100ms
    });

    it('should include encrypted masterKey in token payload', async () => {
      const userId = '123';
      const masterKey = 'base64encodedmasterkey';

      vi.mocked(RefreshTokenModel.create).mockResolvedValue({ _id: 'tokenid' } as any);

      const token = await createRefreshToken(userId, masterKey);
      const decoded = jwt.decode(token) as any;

      expect(decoded.userId).toBe(userId);
      expect(decoded.encryptedMasterKey).toBeDefined();
      expect(decoded.masterKeyIv).toBeDefined();
      expect(decoded.masterKeyAuthTag).toBeDefined();
    });

    it('should produce different encrypted masterKey on each call', async () => {
      const userId = '123';
      const masterKey = 'base64encodedmasterkey';

      vi.mocked(RefreshTokenModel.create).mockResolvedValue({ _id: 'tokenid' } as any);

      const token1 = await createRefreshToken(userId, masterKey);
      const token2 = await createRefreshToken(userId, masterKey);

      const decoded1 = jwt.decode(token1) as any;
      const decoded2 = jwt.decode(token2) as any;

      expect(decoded1.encryptedMasterKey).not.toBe(decoded2.encryptedMasterKey);
      expect(decoded1.masterKeyIv).not.toBe(decoded2.masterKeyIv);
    });
  });

  describe('refresh token decoding and master key extraction', () => {
    it('should decode refresh token and extract userId and masterKey', async () => {
      const userId = '123';
      const masterKey = crypto.randomBytes(32).toString('base64');

      vi.mocked(RefreshTokenModel.create).mockResolvedValue({ _id: 'tokenid' } as any);

      const token = await createRefreshToken(userId, masterKey);
      const decoded = await decodeAndGetMasterKeyFromRefreshToken(token);

      expect(decoded.userId).toBe(userId);
      expect(decoded.masterKey).toBe(masterKey);
    });

    it('should throw error for invalid refresh token', async () => {
      await expect(decodeAndGetMasterKeyFromRefreshToken('invalid.token.here')).rejects.toThrow();
    });

    it('should throw error for expired refresh token', async () => {
      const userId = '123';
      const payload = {
        userId,
        encryptedMasterKey: 'encrypted',
        masterKeyIv: 'iv',
        masterKeyAuthTag: 'tag',
      };
      const expiredToken = jwt.sign(payload, process.env.JWT_SECRET as string, { expiresIn: -1 });

      await expect(decodeAndGetMasterKeyFromRefreshToken(expiredToken)).rejects.toThrow();
    });

    it('should throw error for token with wrong signature', async () => {
      const userId = '123';
      const masterKey = 'base64encodedmasterkey';

      vi.mocked(RefreshTokenModel.create).mockResolvedValue({ _id: 'tokenid' } as any);

      const token = await createRefreshToken(userId, masterKey);
      const tampered = token.slice(0, -5) + 'xxxxx';

      await expect(decodeAndGetMasterKeyFromRefreshToken(tampered)).rejects.toThrow();
    });

    it('should throw error when masterKey encryption is tampered', async () => {
      const userId = '123';
      const masterKey = 'base64encodedmasterkey';

      vi.mocked(RefreshTokenModel.create).mockResolvedValue({ _id: 'tokenid' } as any);

      const token = await createRefreshToken(userId, masterKey);
      const decoded = jwt.decode(token, { complete: true }) as any;

      // Tamper with encrypted master key
      const tampered = {
        ...decoded.payload,
        encryptedMasterKey: 'tampered',
      };
      const tamperedToken = jwt.sign(tampered, process.env.JWT_SECRET as string);

      await expect(decodeAndGetMasterKeyFromRefreshToken(tamperedToken)).rejects.toThrow();
    });
  });

  describe('refresh token revocation', () => {
    it('should mark active refresh tokens as revoked', async () => {
      const userId = '123';

      vi.mocked(RefreshTokenModel.updateMany).mockResolvedValue({ modifiedCount: 2 } as any);

      await revokeActiveRefreshTokens(userId);

      expect(RefreshTokenModel.updateMany).toHaveBeenCalledWith(
        {
          userId,
          $or: [{ revokedAt: { $exists: false } }, { revokedAt: null }],
        },
        { $set: { revokedAt: expect.any(Date) } },
      );
    });

    it('should only revoke non-revoked tokens', async () => {
      const userId = '456';

      vi.mocked(RefreshTokenModel.updateMany).mockResolvedValue({ modifiedCount: 1 } as any);

      await revokeActiveRefreshTokens(userId);

      const call = vi.mocked(RefreshTokenModel.updateMany).mock.calls[0];
      const filter = call[0] as any;

      expect(filter.userId).toBe(userId);
      expect(filter.$or).toEqual([{ revokedAt: { $exists: false } }, { revokedAt: null }]);
    });

    it('should set revokedAt to current date', async () => {
      const userId = '789';
      const beforeCall = Date.now();

      vi.mocked(RefreshTokenModel.updateMany).mockResolvedValue({} as any);

      await revokeActiveRefreshTokens(userId);

      const call = vi.mocked(RefreshTokenModel.updateMany).mock.calls[0];
      const update = call[1] as any;
      const revokedAt = update.$set.revokedAt;
      const afterCall = Date.now();

      expect(revokedAt.getTime()).toBeGreaterThanOrEqual(beforeCall);
      expect(revokedAt.getTime()).toBeLessThanOrEqual(afterCall + 100);
    });
  });
});
