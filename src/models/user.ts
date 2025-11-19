import { Schema, model } from 'mongoose'
import { User } from '../types'

export const UserSchema = new Schema<User>({
  email: String,
  passwordHash: String,

  encryptedMasterKey: String, // base64 ciphertext
  masterKeyIv: String, // base64
  kdfSalt: String, // base64
  kdfIterations: Number,

  createdAt: Date,
  updatedAt: Date,
})

export default model<User>('User', UserSchema, 'users')
