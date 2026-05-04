import { Schema, model } from 'mongoose'

const UserSchema = new Schema({
  email: { type: String, required: true },
  passwordHash: { type: String, required: true },

  kdfSalt: { type: String, required: true },
  masterKeyIv: { type: String, required: true },
  masterKeyAuthTag: { type: String, required: true },
  encryptedMasterKey: { type: String, required: true },

  createdAt: Date,
  updatedAt: Date,
})

const UserModel = model('User', UserSchema, 'users')

export default UserModel
