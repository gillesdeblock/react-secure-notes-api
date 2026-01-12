import { Schema, model } from 'mongoose'

const NoteSchema = new Schema({
  userId: { type: String, required: true },
  iv: { type: String, required: true },

  encryptedTitle: { type: String },
  encryptedShort: { type: String },
  encryptedContent: { type: String },
  titleAuthTag: { type: String, required: true },
  shortAuthTag: { type: String, required: true },
  contentAuthTag: { type: String, required: true },
  tags: [String],

  createdAt: Date,
  updatedAt: Date,
  version: Number,
})

const NoteModel = model('Note', NoteSchema, 'notes')

export default NoteModel
