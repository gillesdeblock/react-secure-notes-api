import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../../app';
import UserModel from '../../models/user';
import NoteModel from '../../models/note';
import RefreshTokenModel from '../../models/refresh-token';

describe('integration: note operations', () => {
  const testEmail = 'note-test@example.com';
  const testPassword = 'test-password-123';
  const otherEmail = 'other-user@example.com';
  const otherPassword = 'other-password-123';

  let userAccessToken: string;
  let otherUserAccessToken: string;
  let noteId: string;

  beforeAll(() => {
    process.env.JWT_SECRET = 'test-secret-key-for-jwt-operations-32-bytes-min';
  });

  beforeEach(async () => {
    // Clear database
    await UserModel.deleteMany({});
    await NoteModel.deleteMany({});
    await RefreshTokenModel.deleteMany({});

    // Register and login first user
    const registerResponse = await request(app).post('/auth/register').send({
      email: testEmail,
      password: testPassword,
    });
    userAccessToken = registerResponse.body.accessToken;

    // Register and login second user
    const otherRegisterResponse = await request(app).post('/auth/register').send({
      email: otherEmail,
      password: otherPassword,
    });
    otherUserAccessToken = otherRegisterResponse.body.accessToken;
  });

  describe('create note', () => {
    it('should create note with valid payload', async () => {
      const response = await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Test Note',
          content: 'This is test content',
        });

      expect(response.status).toBe(201);
      expect(response.body.id).toBeDefined();
      expect(response.body.title).toBe('Test Note');
      expect(response.body.content).toBe('This is test content');
    });

    it('should encrypt note content in database', async () => {
      const response = await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Test Note',
          content: 'This is test content',
        });

      noteId = response.body.id;

      const storedNote = await NoteModel.findById(noteId);
      expect(storedNote?.encryptedTitle).toBeDefined();
      expect(storedNote?.encryptedContent).toBeDefined();
      expect(storedNote?.encryptedTitle).not.toBe('Test Note');
      expect(storedNote?.encryptedContent).not.toBe('This is test content');
    });

    it('should include optional short field', async () => {
      const response = await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Test Note',
          short: 'Short preview',
          content: 'This is test content',
        });

      expect(response.status).toBe(201);
      expect(response.body.short).toBe('Short preview');
    });

    it('should include tags if provided', async () => {
      const response = await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Test Note',
          content: 'This is test content',
          tags: ['important', 'work'],
        });

      expect(response.status).toBe(201);
      const storedNote = await NoteModel.findById(response.body.id);
      expect(storedNote?.tags).toEqual(['important', 'work']);
    });

    it('should set creation timestamp', async () => {
      const response = await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Test Note',
          content: 'This is test content',
        });

      expect(response.body.createdAt).toBeDefined();
      expect(response.body.updatedAt).toBeDefined();
    });

    it('should reject note without title', async () => {
      const response = await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          content: 'This is test content',
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('title and content');
    });

    it('should reject note without content', async () => {
      const response = await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Test Note',
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('title and content');
    });

    it('should reject note creation without authentication', async () => {
      const response = await request(app)
        .post('/notes')
        .send({
          title: 'Test Note',
          content: 'This is test content',
        });

      expect(response.status).toBe(401);
    });
  });

  describe('read notes', () => {
    beforeEach(async () => {
      // Create a note for reading
      const response = await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Test Note 1',
          content: 'Content 1',
        });
      noteId = response.body.id;
    });

    it('should return all notes for user', async () => {
      const response = await request(app)
        .get('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`);

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body)).toBe(true);
      expect(response.body.length).toBeGreaterThanOrEqual(1);
    });

    it('should decrypt note content when reading', async () => {
      const response = await request(app)
        .get('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`);

      const note = response.body[0];
      expect(note.title).toBe('Test Note 1');
      expect(note.content).toBe('Content 1');
      expect(note.encryptedTitle).toBeUndefined();
    });

    it('should return empty array when user has no notes', async () => {
      const response = await request(app)
        .get('/notes')
        .set('Authorization', `Bearer ${otherUserAccessToken}`);

      expect(response.status).toBe(200);
      expect(response.body).toEqual([]);
    });

    it('should only return user-specific notes', async () => {
      // Create a note for other user
      await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${otherUserAccessToken}`)
        .send({
          title: 'Other User Note',
          content: 'Other content',
        });

      const response = await request(app)
        .get('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`);

      expect(response.body.length).toBe(1);
      expect(response.body[0].title).toBe('Test Note 1');
    });

    it('should reject read without authentication', async () => {
      const response = await request(app).get('/notes');

      expect(response.status).toBe(401);
    });

    it('should get single note by id', async () => {
      const response = await request(app)
        .get(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`);

      expect(response.status).toBe(200);
      expect(response.body.id).toBe(noteId);
      expect(response.body.title).toBe('Test Note 1');
    });

    it('should return 404 for non-existent note', async () => {
      const response = await request(app)
        .get(`/notes/507f1f77bcf86cd799439999`)
        .set('Authorization', `Bearer ${userAccessToken}`);

      expect(response.status).toBe(404);
      expect(response.body.message).toContain('not found');
    });

    it('should return 403 when reading other user note', async () => {
      const response = await request(app)
        .get(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${otherUserAccessToken}`);

      expect(response.status).toBe(403);
      expect(response.body.message).toContain('forbidden');
    });
  });

  describe('update note', () => {
    beforeEach(async () => {
      const response = await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Original Title',
          content: 'Original Content',
        });
      noteId = response.body.id;
    });

    it('should update note with new content', async () => {
      const response = await request(app)
        .put(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Updated Title',
          content: 'Updated Content',
        });

      expect(response.status).toBe(200);
      expect(response.body.title).toBe('Updated Title');
      expect(response.body.content).toBe('Updated Content');
    });

    it('should update updatedAt timestamp', async () => {
      const originalNote = await NoteModel.findById(noteId);
      const originalUpdatedAt = originalNote?.updatedAt;

      await new Promise((resolve) => setTimeout(resolve, 10));

      const response = await request(app)
        .put(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Updated Title',
          content: 'Updated Content',
        });

      expect(response.body.updatedAt).not.toBe(originalUpdatedAt);
    });

    it('should preserve createdAt on update', async () => {
      const originalNote = await NoteModel.findById(noteId);
      const originalCreatedAt = originalNote?.createdAt;

      await request(app)
        .put(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Updated Title',
          content: 'Updated Content',
        });

      const updatedNote = await NoteModel.findById(noteId);
      expect(updatedNote?.createdAt).toEqual(originalCreatedAt);
    });

    it('should reject update without title', async () => {
      const response = await request(app)
        .put(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          content: 'Updated Content',
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('title and content');
    });

    it('should reject update without content', async () => {
      const response = await request(app)
        .put(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Updated Title',
        });

      expect(response.status).toBe(400);
    });

    it('should reject update without authentication', async () => {
      const response = await request(app)
        .put(`/notes/${noteId}`)
        .send({
          title: 'Updated Title',
          content: 'Updated Content',
        });

      expect(response.status).toBe(401);
    });
  });

  describe('delete note', () => {
    beforeEach(async () => {
      const response = await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'To Delete',
          content: 'Delete me',
        });
      noteId = response.body.id;
    });

    it('should delete note with valid id', async () => {
      const response = await request(app)
        .delete(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`);

      expect(response.status).toBe(200);
    });

    it('should remove note from database after deletion', async () => {
      await request(app)
        .delete(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`);

      const deletedNote = await NoteModel.findById(noteId);
      expect(deletedNote).toBeNull();
    });

    it('should return 404 when deleting already deleted note', async () => {
      await request(app)
        .delete(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`);

      const response = await request(app)
        .delete(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`);

      expect(response.status).toBe(404);
    });

    it('should return 404 for non-existent note', async () => {
      const response = await request(app)
        .delete(`/notes/507f1f77bcf86cd799439999`)
        .set('Authorization', `Bearer ${userAccessToken}`);

      expect(response.status).toBe(404);
    });

    it('should return 403 when deleting other user note', async () => {
      const response = await request(app)
        .delete(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${otherUserAccessToken}`);

      expect(response.status).toBe(403);
      expect(response.body.message).toContain('forbidden');
    });

    it('should reject delete without authentication', async () => {
      const response = await request(app).delete(`/notes/${noteId}`);

      expect(response.status).toBe(401);
    });

    it('should only delete specified note', async () => {
      // Create another note
      const otherResponse = await request(app)
        .post('/notes')
        .set('Authorization', `Bearer ${userAccessToken}`)
        .send({
          title: 'Keep This',
          content: 'Keep me',
        });
      const keepNoteId = otherResponse.body.id;

      // Delete first note
      await request(app)
        .delete(`/notes/${noteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`);

      // Verify other note still exists
      const response = await request(app)
        .get(`/notes/${keepNoteId}`)
        .set('Authorization', `Bearer ${userAccessToken}`);

      expect(response.status).toBe(200);
      expect(response.body.title).toBe('Keep This');
    });
  });
});
