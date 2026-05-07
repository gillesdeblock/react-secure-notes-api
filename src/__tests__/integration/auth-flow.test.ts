import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../../app';
import UserModel from '../../models/user';
import RefreshTokenModel from '../../models/refresh-token';

describe('integration: auth flow', () => {
  const testEmail = 'test-user@example.com';
  const testPassword = 'test-password-123';

  beforeAll(() => {
    process.env.JWT_SECRET = 'test-secret-key-for-jwt-operations-32-bytes-min';
  });

  beforeEach(async () => {
    // Clear database before each test
    await UserModel.deleteMany({});
    await RefreshTokenModel.deleteMany({});
  });

  describe('user registration', () => {
    it('should create user with valid registration payload', async () => {
      const response = await request(app).post('/auth/register').send({
        email: testEmail,
        password: testPassword,
      });

      expect(response.status).toBe(201);
      expect(response.body.accessToken).toBeDefined();
      expect(typeof response.body.accessToken).toBe('string');
    });

    it('should store password as hash in database', async () => {
      await request(app).post('/auth/register').send({
        email: testEmail,
        password: testPassword,
      });

      const user = await UserModel.findOne({ email: testEmail });
      expect(user).toBeDefined();
      expect(user?.passwordHash).toBeDefined();
      expect(user?.passwordHash).not.toBe(testPassword);
    });

    it('should derive and encrypt master key', async () => {
      await request(app).post('/auth/register').send({
        email: testEmail,
        password: testPassword,
      });

      const user = await UserModel.findOne({ email: testEmail });
      expect(user?.kdfSalt).toBeDefined();
      expect(user?.encryptedMasterKey).toBeDefined();
      expect(user?.masterKeyIv).toBeDefined();
      expect(user?.masterKeyAuthTag).toBeDefined();
    });

    it('should set creation timestamps', async () => {
      await request(app).post('/auth/register').send({
        email: testEmail,
        password: testPassword,
      });

      const user = await UserModel.findOne({ email: testEmail });
      expect(user?.createdAt).toBeDefined();
      expect(user?.updatedAt).toBeDefined();
    });

    it('should return access token with userId and masterKey', async () => {
      const response = await request(app).post('/auth/register').send({
        email: testEmail,
        password: testPassword,
      });

      const decoded = jwt.decode(response.body.accessToken) as any;
      expect(decoded.userId).toBeDefined();
      expect(decoded.masterKey).toBeDefined();
    });

    it('should set refresh token in httpOnly cookie', async () => {
      const response = await request(app).post('/auth/register').send({
        email: testEmail,
        password: testPassword,
      });

      const cookies = response.headers['set-cookie'] as unknown as string[] | undefined;
      expect(cookies).toBeDefined();
      const refreshTokenCookie = cookies?.find((c: string) => c.startsWith('refresh_token='));
      expect(refreshTokenCookie).toBeDefined();
      expect(refreshTokenCookie).toContain('HttpOnly');
      expect(refreshTokenCookie).toContain('Secure');
    });

    it('should reject registration without email', async () => {
      const response = await request(app).post('/auth/register').send({
        password: testPassword,
      });

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('email');
    });

    it('should reject registration without password', async () => {
      const response = await request(app).post('/auth/register').send({
        email: testEmail,
      });

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('password');
    });

    it('should reject duplicate email registration', async () => {
      await request(app).post('/auth/register').send({
        email: testEmail,
        password: testPassword,
      });

      const response = await request(app).post('/auth/register').send({
        email: testEmail,
        password: 'different-password',
      });

      expect(response.status).toBe(409);
      expect(response.body.message).toContain('already taken');
    });
  });

  describe('user login', () => {
    beforeEach(async () => {
      // Register a user for login tests
      await request(app).post('/auth/register').send({
        email: testEmail,
        password: testPassword,
      });
    });

    it('should login with correct credentials', async () => {
      const response = await request(app).post('/auth/login').send({
        email: testEmail,
        password: testPassword,
      });

      expect(response.status).toBe(200);
      expect(response.body.accessToken).toBeDefined();
    });

    it('should reject login with wrong password', async () => {
      const response = await request(app).post('/auth/login').send({
        email: testEmail,
        password: 'wrong-password',
      });

      expect(response.status).toBe(401);
      expect(response.body.message).toContain('invalid credentials');
    });

    it('should reject login with non-existent user', async () => {
      const response = await request(app).post('/auth/login').send({
        email: 'non-existent@example.com',
        password: testPassword,
      });

      expect(response.status).toBe(401);
      expect(response.body.message).toContain('invalid credentials');
    });

    it('should return access token with correct payload', async () => {
      const response = await request(app).post('/auth/login').send({
        email: testEmail,
        password: testPassword,
      });

      const decoded = jwt.decode(response.body.accessToken) as any;
      expect(decoded.userId).toBeDefined();
      expect(decoded.masterKey).toBeDefined();
    });

    it('should set refresh token in cookie on login', async () => {
      const response = await request(app).post('/auth/login').send({
        email: testEmail,
        password: testPassword,
      });

      const cookies = response.headers['set-cookie'] as unknown as string[] | undefined;
      expect(cookies).toBeDefined();
      const refreshTokenCookie = cookies?.find((c: string) => c.startsWith('refresh_token='));
      expect(refreshTokenCookie).toBeDefined();
    });

    it('should reject login without email', async () => {
      const response = await request(app).post('/auth/login').send({
        password: testPassword,
      });

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('email and password are required');
    });

    it('should reject login without password', async () => {
      const response = await request(app).post('/auth/login').send({
        email: testEmail,
      });

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('email and password are required');
    });

    it('should revoke previous refresh tokens on login', async () => {
      // First login
      const response1 = await request(app).post('/auth/login').send({
        email: testEmail,
        password: testPassword,
      });

      const cookies1 = response1.headers['set-cookie'] as unknown as string[] | undefined;
      const refreshToken1 = cookies1
        ?.find((c: string) => c.startsWith('refresh_token='))
        ?.split('=')[1]
        ?.split(';')[0];

      // Second login (should revoke first token)
      await request(app).post('/auth/login').send({
        email: testEmail,
        password: testPassword,
      });

      // Try to use old refresh token
      const reuseResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken1}`);

      expect(reuseResponse.status).toBe(401);
      expect(reuseResponse.body.message).toContain('revoked');
    });
  });

  describe('token refresh', () => {
    let refreshToken: string;

    beforeEach(async () => {
      // Register and login to get refresh token
      const response = await request(app).post('/auth/register').send({
        email: testEmail,
        password: testPassword,
      });

      const cookies = response.headers['set-cookie'] as unknown as string[] | undefined;
      refreshToken = cookies
        ?.find((c: string) => c.startsWith('refresh_token='))
        ?.split('=')[1]
        ?.split(';')[0] || '';
    });

    it('should refresh tokens with valid refresh token', async () => {
      const response = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(response.status).toBe(200);
      expect(response.body.accessToken).toBeDefined();
    });

    it('should return new access token different from old', async () => {
      // Get old token
      const user = await UserModel.findOne({ email: testEmail });
      const oldAccessToken = jwt.sign(
        { userId: user?._id.toString(), masterKey: 'oldkey' },
        process.env.JWT_SECRET as string,
      );

      // Refresh to get new token
      const response = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(response.body.accessToken).not.toBe(oldAccessToken);
    });

    it('should return new refresh token in cookie', async () => {
      const response = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      const newCookies = response.headers['set-cookie'] as unknown as string[] | undefined;
      const newRefreshToken = newCookies
        ?.find((c: string) => c.startsWith('refresh_token='))
        ?.split('=')[1]
        ?.split(';')[0];

      expect(newRefreshToken).toBeDefined();
      expect(newRefreshToken).not.toBe(refreshToken);
    });

    it('should reject refresh without refresh token', async () => {
      const response = await request(app).post('/auth/refresh');

      expect(response.status).toBe(401);
      expect(response.body.message).toContain('refresh_token missing');
    });

    it('should reject refresh with invalid refresh token', async () => {
      const response = await request(app)
        .post('/auth/refresh')
        .set('Cookie', 'refresh_token=invalid.token.here');

      expect(response.status).toBe(401);
      expect(response.body.message).toContain('invalid');
    });

    it('should revoke old refresh token after refresh', async () => {
      // Refresh once
      await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      // Try to use old token again
      const reuseResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(reuseResponse.status).toBe(401);
      expect(reuseResponse.body.message).toContain('revoked');
    });

    it('should allow using new refresh token after refresh', async () => {
      // Refresh once
      const response1 = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      const newCookies = response1.headers['set-cookie'] as unknown as string[] | undefined;
      const newRefreshToken = newCookies
        ?.find((c: string) => c.startsWith('refresh_token='))
        ?.split('=')[1]
        ?.split(';')[0];

      // Refresh again with new token
      const response2 = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${newRefreshToken}`);

      expect(response2.status).toBe(200);
      expect(response2.body.accessToken).toBeDefined();
    });
  });

  describe('user logout', () => {
    let accessToken: string;

    beforeEach(async () => {
      const response = await request(app).post('/auth/register').send({
        email: testEmail,
        password: testPassword,
      });

      accessToken = response.body.accessToken;
    });

    it('should logout with valid access token', async () => {
      const response = await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(response.status).toBe(200);
    });

    it('should clear refresh token cookie on logout', async () => {
      const response = await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`);

      const cookies = response.headers['set-cookie'] as unknown as string[] | undefined;
      const clearCookie = cookies?.find((c: string) => c.startsWith('refresh_token='));
      expect(clearCookie).toBeDefined();
      expect(clearCookie).toContain('Expires=Thu, 01 Jan 1970');
    });

    it('should revoke refresh tokens on logout', async () => {
      // Get refresh token from registration
      const registerResponse = await request(app).post('/auth/register').send({
        email: `another-${testEmail}`,
        password: testPassword,
      });

      const cookies = registerResponse.headers['set-cookie'] as unknown as string[] | undefined;
      const refreshToken = cookies
        ?.find((c: string) => c.startsWith('refresh_token='))
        ?.split('=')[1]
        ?.split(';')[0];

      // Logout
      await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${registerResponse.body.accessToken}`);

      // Try to refresh with old token
      const refreshResponse = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${refreshToken}`);

      expect(refreshResponse.status).toBe(401);
      expect(refreshResponse.body.message).toContain('revoked');
    });

    it('should reject logout without access token', async () => {
      const response = await request(app).post('/auth/logout');

      expect(response.status).toBe(401);
    });

    it('should reject logout with invalid access token', async () => {
      const response = await request(app)
        .post('/auth/logout')
        .set('Authorization', 'Bearer invalid.token.here');

      expect(response.status).toBe(401);
    });

    it('should reject logout with expired access token', async () => {
      const expiredToken = jwt.sign(
        { userId: 'some-id', masterKey: 'some-key' },
        process.env.JWT_SECRET as string,
        { expiresIn: -1 },
      );

      const response = await request(app)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(response.status).toBe(401);
    });
  });
});
