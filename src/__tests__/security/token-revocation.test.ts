import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../../app';
import UserModel from '../../models/user';
import RefreshTokenModel from '../../models/refresh-token';

describe('security: token revocation', () => {
  const testEmail = 'revocation-test@example.com';
  const testPassword = 'test-password-123';

  let accessToken: string;
  let refreshToken: string;

  beforeAll(() => {
    process.env.JWT_SECRET = 'test-secret-key-for-jwt-operations-32-bytes-min';
  });

  beforeEach(async () => {
    await UserModel.deleteMany({});
    await RefreshTokenModel.deleteMany({});

    const registerResponse = await request(app).post('/auth/register').send({
      email: testEmail,
      password: testPassword,
    });

    accessToken = registerResponse.body.accessToken;

    const cookies = registerResponse.headers['set-cookie'];
    refreshToken = cookies
      ?.find((c: string) => c.startsWith('refresh_token='))
      ?.split('=')[1]
      ?.split(';')[0] || '';
  });

  describe('logout revocation', () => {
    it('should mark refresh token as revoked on logout', async () => {
      // Get token doc before logout
      const tokenDocBefore = await RefreshTokenModel.findOne({ hash: refreshToken });
      expect(tokenDocBefore?.revokedAt).toBeUndefined();

      // Logout
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Verify token is revoked
      const tokenDocAfter = await RefreshTokenModel.findOne({ hash: refreshToken });
      expect(tokenDocAfter?.revokedAt).toBeDefined();
      expect(tokenDocAfter?.revokedAt).toBeInstanceOf(Date);
    });

    it('should prevent using revoked token after logout', async () => {
      // Logout
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Try to use revoked token
      const refreshResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(refreshResponse.status).toBe(401);
      expect(refreshResponse.body.message).toContain('revoked');
    });

    it('should reject refresh with revoked token even if JWT is valid', async () => {
      // Logout (marks token as revoked in database)
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Token still has valid JWT signature, but should be rejected due to revocation check
      const refreshResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(refreshResponse.status).toBe(401);
      expect(refreshResponse.body.message).toContain('revoked');
    });

    it('should revoke all user tokens on logout', async () => {
      // Create multiple tokens by doing multiple logins
      const user = await UserModel.findOne({ email: testEmail });
      const userId = user?._id.toString();

      // Get all non-revoked tokens before logout
      const tokensBefore = await RefreshTokenModel.find({
        userId,
        $or: [{ revokedAt: { $exists: false } }, { revokedAt: null }],
      });

      expect(tokensBefore.length).toBeGreaterThan(0);

      // Logout (should revoke all tokens)
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Get all non-revoked tokens after logout
      const tokensAfter = await RefreshTokenModel.find({
        userId,
        $or: [{ revokedAt: { $exists: false } }, { revokedAt: null }],
      });

      expect(tokensAfter.length).toBe(0);
    });
  });

  describe('database revocation enforcement', () => {
    it('should check database for revocation status', async () => {
      // Logout revokes the token
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Verify the refresh endpoint checks both JWT validity AND database revocation
      const refreshResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(refreshResponse.status).toBe(401);
      expect(refreshResponse.body.message).toContain('revoked');
    });

    it('should not rely solely on JWT for revocation', async () => {
      // Even though JWT might not be expired, database revocation should block it
      const tokenDoc = await RefreshTokenModel.findOne({ hash: refreshToken });
      expect((tokenDoc?.expiresAt as Date)?.getTime()).toBeGreaterThan(new Date().getTime());

      // Logout
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Token is not expired but should be rejected due to revocation
      const refreshResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(refreshResponse.status).toBe(401);
    });

    it('should reject revoked token with valid signature if revoked in database', async () => {
      // Logout
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // The token has a valid JWT signature but is marked as revoked in the database
      // This verifies that revocation is enforced at the database layer, not just JWT layer
      const response = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(response.status).toBe(401);
      expect(response.body.message).toContain('revoked');
    });

    it('should handle revocation check even if JWT parsing succeeds', async () => {
      // Verify the token is valid as JWT
      const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET as string);
      expect(decoded).toBeDefined();

      // Logout
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Even though JWT is valid, database revocation should be checked and enforced
      const response = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(response.status).toBe(401);
    });
  });

  describe('revocation persistence', () => {
    it('should persist revocation across multiple requests', async () => {
      // Logout
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Try to use revoked token multiple times
      for (let i = 0; i < 3; i++) {
        const response = await request(app)
          .post('/auth/refresh')
          .set('Cookie', `refresh_token=${refreshToken}`);

        expect(response.status).toBe(401);
        expect(response.body.message).toContain('revoked');
      }
    });

    it('should maintain revocation even after logout is called again', async () => {
      // Create a second access token by logging in again
      const loginResponse = await request(app).post('/auth/login').send({
        email: testEmail,
        password: testPassword,
      });

      const newAccessToken = loginResponse.body.accessToken;

      // Logout with first token
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Try to use first refresh token - should be revoked
      const firstRefresh = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(firstRefresh.status).toBe(401);

      // Logout with second token
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${newAccessToken}`);

      // First refresh token should still be revoked
      const secondRefresh = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(secondRefresh.status).toBe(401);
      expect(secondRefresh.body.message).toContain('revoked');
    });
  });

  describe('revocation prevents session hijacking', () => {
    it('should prevent attacker from using stolen revoked token', async () => {
      // Logout (simulates token being revoked after theft is discovered)
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Attacker tries to use stolen token
      const attackResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(attackResponse.status).toBe(401);
      expect(attackResponse.body.message).toContain('revoked');
    });

    it('should not allow hijacked token to create new sessions', async () => {
      // Attacker obtains refresh token
      const stolenToken = refreshToken;

      // User logs out (revokes token)
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Attacker tries to get new tokens using stolen token
      const newSessionResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${stolenToken}`);

      expect(newSessionResponse.status).toBe(401);
      expect(newSessionResponse.body.accessToken).toBeUndefined();
    });
  });
});
