import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../../app';
import UserModel from '../../models/user';
import RefreshTokenModel from '../../models/refresh-token';

describe('security: token rotation', () => {
  const testEmail = 'rotation-test@example.com';
  const testPassword = 'test-password-123';

  let refreshToken: string;
  let newRefreshToken: string;

  beforeAll(() => {
    process.env.JWT_SECRET = 'test-secret-key-for-jwt-operations-32-bytes-min';
  });

  beforeEach(async () => {
    await UserModel.deleteMany({});
    await RefreshTokenModel.deleteMany({});

    // Register and get initial refresh token
    const registerResponse = await request(app).post('/auth/register').send({
      email: testEmail,
      password: testPassword,
    });

    const cookies = registerResponse.headers['set-cookie'] as unknown as string[] | undefined;
    refreshToken = cookies
      ?.find((c: string) => c.startsWith('refresh_token='))
      ?.split('=')[1]
      ?.split(';')[0] || '';
  });

  describe('refresh token invalidation', () => {
    it('should revoke old refresh token in database after refresh', async () => {
      // Get the old token from database before refresh
      const oldTokenDoc = await RefreshTokenModel.findOne({ hash: refreshToken });
      expect(oldTokenDoc?.revokedAt).toBeUndefined();

      // Perform refresh
      const refreshResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(refreshResponse.status).toBe(200);

      // Verify old token is marked as revoked
      const revokedTokenDoc = await RefreshTokenModel.findOne({ hash: refreshToken });
      expect(revokedTokenDoc?.revokedAt).toBeDefined();
      expect(revokedTokenDoc?.revokedAt).toBeInstanceOf(Date);
    });

    it('should reject reuse of revoked refresh token', async () => {
      // Perform first refresh (old token gets revoked)
      const firstRefresh = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(firstRefresh.status).toBe(200);
      newRefreshToken = (firstRefresh.headers['set-cookie'] as unknown as string[] | undefined)
        ?.find((c: string) => c.startsWith('refresh_token='))
        ?.split('=')[1]
        ?.split(';')[0] || '';

      // Try to use old revoked token again
      const reuseResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(reuseResponse.status).toBe(401);
      expect(reuseResponse.body.message).toContain('revoked');
    });

    it('should allow using new refresh token after rotation', async () => {
      // Perform first refresh
      const firstRefresh = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      const newCookies = firstRefresh.headers['set-cookie'] as unknown as string[] | undefined;
      newRefreshToken = newCookies
        ?.find((c: string) => c.startsWith('refresh_token='))
        ?.split('=')[1]
        ?.split(';')[0] || '';

      // Use new token for second refresh
      const secondRefresh = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${newRefreshToken}`);

      expect(secondRefresh.status).toBe(200);
      expect(secondRefresh.body.accessToken).toBeDefined();
    });

    it('should not allow token reuse even with valid JWT signature', async () => {
      // Revoke the old token by refreshing
      await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      // The token still has valid JWT signature, but should be rejected due to revocation in database
      const reuseResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(reuseResponse.status).toBe(401);
      expect(reuseResponse.body.message).toContain('revoked');
    });

    it('should prevent token replay attacks by rotating on every refresh', async () => {
      const tokens: string[] = [refreshToken];

      // Perform multiple refreshes and collect tokens
      for (let i = 0; i < 3; i++) {
        const refreshResponse = await request(app)
          .post('/auth/refresh')
          .set('Cookie', `refresh_token=${tokens[tokens.length - 1]}`);

        const newCookies = refreshResponse.headers['set-cookie'] as unknown as string[] | undefined;
        const newToken = newCookies
          ?.find((c: string) => c.startsWith('refresh_token='))
          ?.split('=')[1]
          ?.split(';')[0] || '';

        tokens.push(newToken);
      }

      // Try to replay old tokens - all except the last should be revoked
      for (let i = 0; i < tokens.length - 1; i++) {
        const replayResponse = await request(app)
          .post('/auth/refresh')
          .set('Cookie', `refresh_token=${tokens[i]}`);

        expect(replayResponse.status).toBe(401);
        expect(replayResponse.body.message).toContain('revoked');
      }

      // Only the latest token should work
      const validResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${tokens[tokens.length - 1]}`);

      expect(validResponse.status).toBe(200);
    });
  });

  describe('access token independence', () => {
    it('should allow using old access token until expiration', async () => {
      // Get initial access token
      const initialResponse = await request(app).post('/auth/register').send({
        email: `another-${testEmail}`,
        password: testPassword,
      });
      const oldAccessToken = initialResponse.body.accessToken;

      // Refresh to get new tokens
      const cookies = initialResponse.headers['set-cookie'] as unknown as string[] | undefined;
      const refreshToken2 = cookies
        ?.find((c: string) => c.startsWith('refresh_token='))
        ?.split('=')[1]
        ?.split(';')[0] || '';

      await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken2}`);

      // Old access token should still be valid (not revoked)
      // We can verify this by using it to access protected endpoint
      const response = await request(app)
        .get('/notes')
        .set('Authorization', `Bearer ${oldAccessToken}`);

      expect(response.status).toBe(200);
    });

    it('should not revoke access token on refresh', async () => {
      // Get initial tokens
      const registerResponse = await request(app).post('/auth/register').send({
        email: `token-indep-${testEmail}`,
        password: testPassword,
      });

      const oldAccessToken = registerResponse.body.accessToken;
      const cookies = registerResponse.headers['set-cookie'] as unknown as string[] | undefined;
      const oldRefreshToken = cookies
        ?.find((c: string) => c.startsWith('refresh_token='))
        ?.split('=')[1]
        ?.split(';')[0] || '';

      // Refresh
      await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${oldRefreshToken}`);

      // Old access token should still work
      const protectedResponse = await request(app)
        .get('/notes')
        .set('Authorization', `Bearer ${oldAccessToken}`);

      expect(protectedResponse.status).toBe(200);
    });

    it('should allow access token to work even after refresh token is revoked by logout', async () => {
      const registerResponse = await request(app).post('/auth/register').send({
        email: `logout-test-${testEmail}`,
        password: testPassword,
      });

      const accessToken = registerResponse.body.accessToken;

      // Logout (revokes refresh token)
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      // Access token should still work (until expiration)
      const notesResponse = await request(app)
        .get('/notes')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(notesResponse.status).toBe(200);
    });
  });

  describe('token rotation limits blast radius', () => {
    it('should limit damage from leaked token to only that token', async () => {
      const tokens: string[] = [refreshToken];

      // Generate a chain of tokens
      for (let i = 0; i < 5; i++) {
        const refreshResponse = await request(app)
          .post('/auth/refresh')
          .set('Cookie', `refresh_token=${tokens[tokens.length - 1]}`);

        const newCookies = refreshResponse.headers['set-cookie'] as unknown as string[] | undefined;
        const newToken = newCookies
          ?.find((c: string) => c.startsWith('refresh_token='))
          ?.split('=')[1]
          ?.split(';')[0] || '';

        tokens.push(newToken);
      }

      // Simulate token leak: attacker gets token at position 2
      const leakedTokenIndex = 2;

      // Attacker tries to use leaked token
      const attackResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${tokens[leakedTokenIndex]}`);

      expect(attackResponse.status).toBe(401);
      expect(attackResponse.body.message).toContain('revoked');

      // User can still use the current token (token rotation limits damage)
      const userResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${tokens[tokens.length - 1]}`);

      expect(userResponse.status).toBe(200);
    });

    it('should not allow token chain replacement attacks', async () => {
      // Perform refresh to get new token
      const firstRefresh = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      const newCookies = firstRefresh.headers['set-cookie'] as unknown as string[] | undefined;
      const newToken = newCookies
        ?.find((c: string) => c.startsWith('refresh_token='))
        ?.split('=')[1]
        ?.split(';')[0] || '';

      // Attacker tries to use old token to get new tokens
      const attackResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(attackResponse.status).toBe(401);

      // But user can continue with legitimate token
      const userResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${newToken}`);

      expect(userResponse.status).toBe(200);
    });
  });
});
