import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../../app';

describe('security: CORS validation', () => {
  beforeAll(() => {
    process.env.JWT_SECRET = 'test-secret-key-for-jwt-operations-32-bytes-min';
  });

  describe('allowed origins', () => {
    it('should allow requests from https://secure-notes.gillesdeblock.com', async () => {
      const response = await request(app)
        .get('/health')
        .set('Origin', 'https://secure-notes.gillesdeblock.com');

      expect(response.headers['access-control-allow-origin']).toBe(
        'https://secure-notes.gillesdeblock.com',
      );
    });

    it('should allow requests from http://localhost:5173', async () => {
      const response = await request(app).get('/health').set('Origin', 'http://localhost:5173');

      expect(response.headers['access-control-allow-origin']).toBe('http://localhost:5173');
    });

    it('should allow requests without Origin header', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
    });

    it('should allow OPTIONS (preflight) for allowed origins', async () => {
      const response = await request(app)
        .options('/health')
        .set('Origin', 'https://secure-notes.gillesdeblock.com')
        .set('Access-Control-Request-Method', 'POST');

      expect(response.status).toBe(204);
      expect(response.headers['access-control-allow-origin']).toBe(
        'https://secure-notes.gillesdeblock.com',
      );
    });

    it('should include credentials flag for allowed origins', async () => {
      const response = await request(app)
        .get('/health')
        .set('Origin', 'https://secure-notes.gillesdeblock.com');

      expect(response.headers['access-control-allow-credentials']).toBe('true');
    });

    it('should allow credentials in CORS requests', async () => {
      const response = await request(app)
        .get('/health')
        .set('Origin', 'http://localhost:5173')
        .set('Cookie', 'test=value');

      expect(response.headers['access-control-allow-credentials']).toBe('true');
    });
  });

  describe('blocked origins', () => {
    it('should reject requests from unauthorized origin', async () => {
      const response = await request(app)
        .get('/health')
        .set('Origin', 'https://malicious-site.com');

      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('should reject requests from arbitrary localhost port', async () => {
      const response = await request(app)
        .get('/health')
        .set('Origin', 'http://localhost:3000');

      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('should reject requests from http version of secure origin', async () => {
      const response = await request(app)
        .get('/health')
        .set('Origin', 'http://secure-notes.gillesdeblock.com');

      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('should reject requests from subdomain of allowed origin', async () => {
      const response = await request(app)
        .get('/health')
        .set('Origin', 'https://api.secure-notes.gillesdeblock.com');

      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('should reject requests from similar but different domain', async () => {
      const response = await request(app)
        .get('/health')
        .set('Origin', 'https://secure-notes-gillesdeblock.com');

      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('should block CORS preflight for unauthorized origin', async () => {
      const response = await request(app)
        .options('/health')
        .set('Origin', 'https://evil.com')
        .set('Access-Control-Request-Method', 'POST');

      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('should not return sensitive data for blocked origins', async () => {
      const response = await request(app)
        .get('/notes')
        .set('Origin', 'https://attacker.com');

      // CORS should be denied (no header)
      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });
  });

  describe('CORS security properties', () => {
    it('should prevent cross-origin cookie access by default', async () => {
      // Browser would block this request if CORS headers are not present
      const response = await request(app)
        .get('/health')
        .set('Origin', 'https://unauthorized.com');

      // No CORS header = browser blocks it
      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('should require credentials flag to be explicitly set', async () => {
      const response = await request(app)
        .get('/health')
        .set('Origin', 'https://secure-notes.gillesdeblock.com');

      // Should explicitly allow credentials for cookie sharing
      expect(response.headers['access-control-allow-credentials']).toBe('true');
    });

    it('should not allow wildcard origin with credentials', async () => {
      // This is a security best practice - the app should NOT use "*" with credentials
      const response = await request(app)
        .get('/health')
        .set('Origin', 'https://any-origin.com');

      const acaoHeader = response.headers['access-control-allow-origin'];
      // If wildcard is used with credentials, this is a security issue
      // We're verifying it's NOT "*"
      expect(acaoHeader).not.toBe('*');
    });

    it('should properly handle Origin header variations', async () => {
      const response1 = await request(app)
        .get('/health')
        .set('Origin', 'HTTPS://SECURE-NOTES.GILLESDEBLOCK.COM');

      // Should be case-sensitive (browser enforces this)
      expect(response1.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('should block null Origin for security', async () => {
      const response = await request(app).get('/health').set('Origin', 'null');

      // null origin should be treated as blocked
      expect(response.headers['access-control-allow-origin']).not.toBe('null');
    });
  });

  describe('CORS with protected endpoints', () => {
    it('should enforce CORS on protected endpoints', async () => {
      const response = await request(app)
        .get('/notes')
        .set('Origin', 'https://evil.com');

      // CORS should be enforced even on protected endpoints
      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('should allow protected endpoint access from allowed origin', async () => {
      // This would require a valid auth token
      // Just verify CORS headers are set correctly
      const response = await request(app)
        .get('/notes')
        .set('Origin', 'https://secure-notes.gillesdeblock.com');

      // CORS should be allowed (might get 401 due to missing auth, but CORS is allowed)
      expect(response.headers['access-control-allow-origin']).toBe(
        'https://secure-notes.gillesdeblock.com',
      );
    });

    it('should include credentials header for protected endpoints', async () => {
      const response = await request(app)
        .get('/notes')
        .set('Origin', 'http://localhost:5173');

      expect(response.headers['access-control-allow-credentials']).toBe('true');
    });
  });

  describe('CORS prevents CSRF', () => {
    it('should require explicit CORS permission for state-changing requests', async () => {
      // POST request from unauthorized origin
      const response = await request(app)
        .post('/notes')
        .set('Origin', 'https://csrf-attacker.com')
        .send({ title: 'Test', content: 'Test' });

      // Browser would block this due to CORS
      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('should allow state-changing requests only from allowed origins', async () => {
      const response = await request(app)
        .post('/notes')
        .set('Origin', 'https://secure-notes.gillesdeblock.com')
        .send({ title: 'Test', content: 'Test' });

      // CORS header should be present (might get 401 due to auth, but CORS is allowed)
      expect(response.headers['access-control-allow-origin']).toBe(
        'https://secure-notes.gillesdeblock.com',
      );
    });

    it('should require preflight for certain request types', async () => {
      const response = await request(app)
        .options('/notes')
        .set('Origin', 'https://secure-notes.gillesdeblock.com')
        .set('Access-Control-Request-Method', 'DELETE');

      expect(response.status).toBe(204);
      expect(response.headers['access-control-allow-origin']).toBe(
        'https://secure-notes.gillesdeblock.com',
      );
    });
  });
});
