import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import useAccessToken from '../../../middleware/use-access-token';

describe('middleware: use-access-token', () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;
  let jsonMock: any;
  let statusMock: any;

  beforeAll(() => {
    process.env.JWT_SECRET = 'test-secret-key-for-jwt-operations-32-bytes-min';
  });

  beforeEach(() => {
    jsonMock = vi.fn().mockReturnValue(undefined);
    statusMock = vi.fn().mockReturnValue({ json: jsonMock });

    req = {
      headers: {},
    };

    res = {
      status: statusMock,
      json: jsonMock,
    };

    next = vi.fn();
  });

  describe('valid token', () => {
    it('should extract token from Authorization header', () => {
      const payload = { userId: '123', masterKey: 'base64key' };
      const token = jwt.sign(payload, process.env.JWT_SECRET as string);
      req.headers = { authorization: `Bearer ${token}` };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(next).toHaveBeenCalled();
    });

    it('should verify token signature', () => {
      const payload = { userId: '123', masterKey: 'base64key' };
      const token = jwt.sign(payload, process.env.JWT_SECRET as string);
      req.headers = { authorization: `Bearer ${token}` };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should add decodedToken to request', () => {
      const payload = { userId: '456', masterKey: 'anotherkey' };
      const token = jwt.sign(payload, process.env.JWT_SECRET as string);
      req.headers = { authorization: `Bearer ${token}` };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect((req as any).decodedToken).toBeDefined();
      expect((req as any).decodedToken.userId).toBe('456');
      expect((req as any).decodedToken.masterKey).toBe('anotherkey');
    });

    it('should call next() on successful verification', () => {
      const payload = { userId: '123', masterKey: 'base64key' };
      const token = jwt.sign(payload, process.env.JWT_SECRET as string);
      req.headers = { authorization: `Bearer ${token}` };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should respect custom verify options', () => {
      const payload = { userId: '123', masterKey: 'base64key' };
      const token = jwt.sign(payload, process.env.JWT_SECRET as string);
      req.headers = { authorization: `Bearer ${token}` };

      const verifyOptions = { algorithms: ['HS256'] as jwt.Algorithm[] };
      const middleware = useAccessToken(verifyOptions);
      middleware(req as Request, res as Response, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe('missing token', () => {
    it('should return 401 when Authorization header missing', () => {
      req.headers = {};

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: 'unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 when Authorization header is empty', () => {
      req.headers = { authorization: '' };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: 'unauthorized' });
    });

    it('should return 401 when Authorization header does not start with Bearer', () => {
      req.headers = { authorization: 'Basic sometoken' };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: 'unauthorized' });
    });

    it('should return 401 when only Bearer prefix without token', () => {
      req.headers = { authorization: 'Bearer ' };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: 'unauthorized' });
    });
  });

  describe('invalid token', () => {
    it('should return 401 when token is malformed', () => {
      req.headers = { authorization: 'Bearer not.a.valid.token' };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 when token signature is invalid', () => {
      const payload = { userId: '123', masterKey: 'base64key' };
      const token = jwt.sign(payload, 'wrong-secret-key');
      req.headers = { authorization: `Bearer ${token}` };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 when token is expired', () => {
      const payload = { userId: '123', masterKey: 'base64key' };
      const token = jwt.sign(payload, process.env.JWT_SECRET as string, { expiresIn: -1 });
      req.headers = { authorization: `Bearer ${token}` };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('invalid payload', () => {
    it('should return 401 when payload missing userId', () => {
      const payload = { masterKey: 'base64key' };
      const token = jwt.sign(payload, process.env.JWT_SECRET as string);
      req.headers = { authorization: `Bearer ${token}` };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: 'authentication failed' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 when payload missing masterKey', () => {
      const payload = { userId: '123' };
      const token = jwt.sign(payload, process.env.JWT_SECRET as string);
      req.headers = { authorization: `Bearer ${token}` };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({ message: 'authentication failed' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 when payload is empty object', () => {
      const token = jwt.sign({}, process.env.JWT_SECRET as string);
      req.headers = { authorization: `Bearer ${token}` };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('edge cases', () => {
    it('should handle Authorization header with multiple spaces', () => {
      const payload = { userId: '123', masterKey: 'base64key' };
      const token = jwt.sign(payload, process.env.JWT_SECRET as string);
      req.headers = { authorization: `Bearer  ${token}` };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      // Should fail because token will be "Bearer {token}"
      expect(statusMock).toHaveBeenCalledWith(401);
    });

    it('should be case-sensitive for Bearer prefix', () => {
      const payload = { userId: '123', masterKey: 'base64key' };
      const token = jwt.sign(payload, process.env.JWT_SECRET as string);
      req.headers = { authorization: `bearer ${token}` };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(401);
    });

    it('should not call next() on error', () => {
      req.headers = { authorization: 'Bearer invalid' };

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(next).not.toHaveBeenCalled();
    });

    it('should only send one response', () => {
      req.headers = {};

      const middleware = useAccessToken();
      middleware(req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledTimes(1);
      expect(jsonMock).toHaveBeenCalledTimes(1);
    });
  });
});
