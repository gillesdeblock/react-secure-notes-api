import { Schema, model } from 'mongoose'
import { RefreshToken } from '../types/refresh-token'

export const RefreshTokenSchema = new Schema<RefreshToken>({
  userId: Schema.ObjectId,
  hash: String,
  expiresAt: Date,
  revokedAt: Date,
})

export default model<RefreshToken>('RefreshToken', RefreshTokenSchema, 'refreshtokens')
