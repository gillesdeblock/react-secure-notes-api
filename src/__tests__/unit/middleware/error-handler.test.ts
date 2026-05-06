import { describe, it, expect, beforeEach, vi } from 'vitest';
import mongoose from 'mongoose';
import { Request, Response, NextFunction } from 'express';
import errorHandler from '../../../middleware/error-handler';

describe('middleware: error-handler', () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;
  let jsonMock: any;
  let statusMock: any;

  beforeEach(() => {
    jsonMock = vi.fn().mockReturnValue(undefined);
    statusMock = vi.fn().mockReturnValue({ json: jsonMock });

    req = {};
    res = {
      status: statusMock,
      json: jsonMock,
    };

    next = vi.fn();
  });

  describe('ValidationError', () => {
    it('should return 400 for Mongoose ValidationError', () => {
      const error = new mongoose.Error.ValidationError();
      error.errors.email = new mongoose.Error.ValidatorError({
        message: 'Invalid email format',
      });

      errorHandler(error, req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(400);
    });

    it('should include validation error message in response', () => {
      const error = new mongoose.Error.ValidationError();
      error.errors.email = new mongoose.Error.ValidatorError({
        message: 'Invalid email format',
      });

      errorHandler(error, req as Request, res as Response, next);

      expect(jsonMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Validation error',
          fields: expect.any(Object),
        }),
      );
    });

    it('should include field-specific errors', () => {
      const error = new mongoose.Error.ValidationError();
      error.errors.email = new mongoose.Error.ValidatorError({
        message: 'Invalid email format',
      });
      error.errors.username = new mongoose.Error.ValidatorError({
        message: 'Username is required',
      });

      errorHandler(error, req as Request, res as Response, next);

      const response = jsonMock.mock.calls[0][0];
      expect(response.fields.email).toBe('Invalid email format');
      expect(response.fields.username).toBe('Username is required');
    });

    it('should handle CastError within ValidationError', () => {
      const error = new mongoose.Error.ValidationError();
      const castError = new mongoose.Error.CastError('ObjectId', '123abc', 'userId');
      error.errors.userId = castError;

      errorHandler(error, req as Request, res as Response, next);

      const response = jsonMock.mock.calls[0][0];
      expect(response.fields.userId).toContain('Invalid value for field');
    });

    it('should handle multiple field validation errors', () => {
      const error = new mongoose.Error.ValidationError();
      error.errors.email = new mongoose.Error.ValidatorError({
        message: 'Email is invalid',
      });
      error.errors.password = new mongoose.Error.ValidatorError({
        message: 'Password too short',
      });
      error.errors.age = new mongoose.Error.ValidatorError({
        message: 'Age must be number',
      });

      errorHandler(error, req as Request, res as Response, next);

      const response = jsonMock.mock.calls[0][0];
      expect(Object.keys(response.fields).length).toBe(3);
    });
  });

  describe('CastError', () => {
    it('should return 400 for Mongoose CastError', () => {
      const error = new mongoose.Error.CastError('ObjectId', 'invalid-id', 'userId');

      errorHandler(error, req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(400);
    });

    it('should include field name in CastError response', () => {
      const error = new mongoose.Error.CastError('ObjectId', 'invalid-id', 'userId');

      errorHandler(error, req as Request, res as Response, next);

      const response = jsonMock.mock.calls[0][0];
      expect(response.message).toContain('userId');
    });

    it('should handle CastError on different field types', () => {
      const error = new mongoose.Error.CastError('Number', 'not-a-number', 'age');

      errorHandler(error, req as Request, res as Response, next);

      const response = jsonMock.mock.calls[0][0];
      expect(response.message).toContain('age');
    });

    it('should distinguish between CastError and ValidationError', () => {
      const castError = new mongoose.Error.CastError('ObjectId', 'invalid', 'id');
      const validationError = new mongoose.Error.ValidationError();

      errorHandler(castError, req as Request, res as Response, next);
      const castResponse = jsonMock.mock.calls[0][0];

      jsonMock.mockClear();

      errorHandler(validationError, req as Request, res as Response, next);
      const validationResponse = jsonMock.mock.calls[0][0];

      expect(castResponse.message).toBeTruthy();
      expect(validationResponse.fields).toBeDefined();
    });
  });

  describe('Duplicate Key Error (E11000)', () => {
    it('should return 409 for duplicate key error', () => {
      const error = new Error('Duplicate key');
      (error as any).code = 11000;
      (error as any).keyValue = { email: 'existing@example.com' };

      errorHandler(error, req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(409);
    });

    it('should identify the duplicate field', () => {
      const error = new Error('Duplicate key');
      (error as any).code = 11000;
      (error as any).keyValue = { email: 'existing@example.com' };

      errorHandler(error, req as Request, res as Response, next);

      const response = jsonMock.mock.calls[0][0];
      expect(response.message).toContain('email');
      expect(response.message).toContain('already exists');
    });

    it('should handle duplicate key on different fields', () => {
      const error = new Error('Duplicate key');
      (error as any).code = 11000;
      (error as any).keyValue = { username: 'taken-username' };

      errorHandler(error, req as Request, res as Response, next);

      const response = jsonMock.mock.calls[0][0];
      expect(response.message).toContain('username');
    });

    it('should handle multiple duplicate keys', () => {
      const error = new Error('Duplicate key');
      (error as any).code = 11000;
      (error as any).keyValue = { email: 'existing@example.com', username: 'taken' };

      errorHandler(error, req as Request, res as Response, next);

      const response = jsonMock.mock.calls[0][0];
      // Should include the first key
      expect(response.message).toContain('already exists');
    });
  });

  describe('Unexpected Errors', () => {
    it('should return 500 for unexpected error', () => {
      const error = new Error('Something went wrong');

      errorHandler(error, req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(500);
    });

    it('should return generic error message for unexpected error', () => {
      const error = new Error('Something went wrong');

      errorHandler(error, req as Request, res as Response, next);

      const response = jsonMock.mock.calls[0][0];
      expect(response.message).toBe('unexpected error');
    });

    it('should handle plain object errors', () => {
      const error = { message: 'Some error' };

      errorHandler(error, req as Request, res as Response, next);

      const response = jsonMock.mock.calls[0][0];
      expect(response.message).toBe('unexpected error');
    });

    it('should handle errors without message property', () => {
      const error = {};

      errorHandler(error, req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalledWith(500);
    });

    it('should not expose internal error details', () => {
      const error = new Error('Database connection failed');
      (error as any).stack = 'sensitive stack trace';
      (error as any).config = { apiKey: 'secret' };

      errorHandler(error, req as Request, res as Response, next);

      const response = jsonMock.mock.calls[0][0];
      expect(response).not.toHaveProperty('stack');
      expect(response).not.toHaveProperty('config');
      expect(response.message).toBe('unexpected error');
    });
  });

  describe('response format', () => {
    it('should always return JSON', () => {
      const error = new Error('Test error');

      errorHandler(error, req as Request, res as Response, next);

      expect(jsonMock).toHaveBeenCalled();
    });

    it('should always set a status code', () => {
      const error = new Error('Test error');

      errorHandler(error, req as Request, res as Response, next);

      expect(statusMock).toHaveBeenCalled();
    });

    it('should return response from status().json() call', () => {
      const error = new Error('Test error');

      const result = errorHandler(error, req as Request, res as Response, next);

      expect(result).toBe(undefined);
    });

    it('should not call next()', () => {
      const error = new Error('Test error');

      errorHandler(error, req as Request, res as Response, next);

      expect(next).not.toHaveBeenCalled();
    });
  });
});
