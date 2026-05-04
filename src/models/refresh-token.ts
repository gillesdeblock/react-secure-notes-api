import { Schema, model } from 'mongoose'

export const RefreshTokenSchema = new Schema({
  userId: { type: Schema.ObjectId },

  hash: { type: String, required: true },
  expiresAt: Date,
  revokedAt: Date,
})

const RefreshTokenModel = model('RefreshToken', RefreshTokenSchema, 'refreshtokens')

export default RefreshTokenModel
