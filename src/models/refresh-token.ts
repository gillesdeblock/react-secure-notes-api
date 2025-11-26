import { Schema, model } from 'mongoose'

export const RefreshTokenSchema = new Schema({
  userId: Schema.ObjectId,

  hash: String,
  expiresAt: Date,
  revokedAt: Date,
})

const RefreshTokenModel = model('RefreshToken', RefreshTokenSchema, 'refreshtokens')

export default RefreshTokenModel
