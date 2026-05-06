import { describe, it, expect } from 'vitest';
import { hasProperties, sanitizeObjectForDb } from '../../../lib/utils';

describe('utils', () => {
  describe('hasProperties', () => {
    it('should return true when all properties exist', () => {
      const obj = { id: '123', name: 'test', email: 'test@example.com' };
      expect(hasProperties(obj, 'id', 'name')).toBe(true);
    });

    it('should return false when any property is missing', () => {
      const obj = { id: '123', name: 'test' };
      expect(hasProperties(obj, 'id', 'email')).toBe(false);
    });

    it('should return false when property is undefined', () => {
      const obj = { id: '123', name: undefined };
      expect(hasProperties(obj, 'id', 'name')).toBe(false);
    });

    it('should return true for single property check', () => {
      const obj = { id: '123' };
      expect(hasProperties(obj, 'id')).toBe(true);
    });

    it('should return false for single missing property', () => {
      const obj = { id: '123' };
      expect(hasProperties(obj, 'name')).toBe(false);
    });

    it('should return true when checking multiple properties that all exist', () => {
      const obj = { a: 1, b: 2, c: 3, d: 4 };
      expect(hasProperties(obj, 'a', 'c', 'd')).toBe(true);
    });

    it('should return false when one of multiple properties is missing', () => {
      const obj = { a: 1, b: 2, c: 3 };
      expect(hasProperties(obj, 'a', 'b', 'x')).toBe(false);
    });

    it('should handle null values as existing properties', () => {
      const obj = { id: '123', value: null };
      expect(hasProperties(obj, 'id', 'value')).toBe(true);
    });

    it('should handle 0 and false as existing properties', () => {
      const obj = { count: 0, active: false };
      expect(hasProperties(obj, 'count', 'active')).toBe(true);
    });

    it('should handle empty string as existing property', () => {
      const obj = { name: '' };
      expect(hasProperties(obj, 'name')).toBe(true);
    });
  });

  describe('sanitizeObjectForDb', () => {
    it('should convert Buffer to base64 string', () => {
      const buffer = Buffer.from('test');
      const obj = { id: '123', data: buffer };
      const result = sanitizeObjectForDb(obj);

      expect(result.id).toBe('123');
      expect(result.data).toBe(buffer.toString('base64'));
      expect(typeof result.data).toBe('string');
    });

    it('should preserve non-Buffer string values', () => {
      const obj = { id: '123', name: 'test' };
      const result = sanitizeObjectForDb(obj);

      expect(result.id).toBe('123');
      expect(result.name).toBe('test');
    });

    it('should preserve number values', () => {
      const obj = { count: 42, decimal: 3.14 };
      const result = sanitizeObjectForDb(obj);

      expect(result.count).toBe(42);
      expect(result.decimal).toBe(3.14);
    });

    it('should preserve boolean values', () => {
      const obj = { active: true, verified: false };
      const result = sanitizeObjectForDb(obj);

      expect(result.active).toBe(true);
      expect(result.verified).toBe(false);
    });

    it('should handle mixed Buffer and non-Buffer values', () => {
      const buffer = Buffer.from('secret');
      const obj = { id: '123', secret: buffer, name: 'test', count: 5 };
      const result = sanitizeObjectForDb(obj);

      expect(result.id).toBe('123');
      expect(result.secret).toBe(buffer.toString('base64'));
      expect(result.name).toBe('test');
      expect(result.count).toBe(5);
    });

    it('should handle multiple Buffers in same object', () => {
      const buffer1 = Buffer.from('secret1');
      const buffer2 = Buffer.from('secret2');
      const obj = { secret1: buffer1, secret2: buffer2 };
      const result = sanitizeObjectForDb(obj);

      expect(result.secret1).toBe(buffer1.toString('base64'));
      expect(result.secret2).toBe(buffer2.toString('base64'));
    });

    it('should preserve null values', () => {
      const obj = { id: '123', optional: null };
      const result = sanitizeObjectForDb(obj);

      expect(result.id).toBe('123');
      expect(result.optional).toBeNull();
    });

    it('should preserve undefined values', () => {
      const obj = { id: '123', optional: undefined };
      const result = sanitizeObjectForDb(obj);

      expect(result.id).toBe('123');
      expect(result.optional).toBeUndefined();
    });

    it('should handle empty Buffer', () => {
      const buffer = Buffer.from('');
      const obj = { data: buffer };
      const result = sanitizeObjectForDb(obj);

      expect(result.data).toBe('');
      expect(typeof result.data).toBe('string');
    });

    it('should handle Buffer with special characters', () => {
      const buffer = Buffer.from('special!@#$%^&*()');
      const obj = { data: buffer };
      const result = sanitizeObjectForDb(obj);

      expect(result.data).toBe(buffer.toString('base64'));
      expect(Buffer.from(result.data, 'base64').toString()).toBe('special!@#$%^&*()');
    });

    it('should not modify original object', () => {
      const buffer = Buffer.from('test');
      const original = { id: '123', data: buffer };
      const sanitized = sanitizeObjectForDb(original);

      expect(original.data).toBeInstanceOf(Buffer);
      expect(sanitized.data).toBe('dGVzdA==');
    });

    it('should handle objects with Date values', () => {
      const date = new Date('2026-05-06');
      const obj = { id: '123', createdAt: date };
      const result = sanitizeObjectForDb(obj);

      expect(result.id).toBe('123');
      expect(result.createdAt).toBe(date);
    });

    it('should handle nested objects', () => {
      const obj = { id: '123', nested: { name: 'test' } };
      const result = sanitizeObjectForDb(obj);

      expect(result.id).toBe('123');
      expect(result.nested).toEqual({ name: 'test' });
    });
  });
});
