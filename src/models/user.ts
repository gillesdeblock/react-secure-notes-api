import { Schema, model } from 'mongoose'

const UserSchema = new Schema({
  email: { type: String, required: true },
  passwordHash: { type: String, required: true },

  kdfSalt: String,
  masterKeyIv: String,
  masterKeyAuthTag: String,
  encryptedMasterKey: String,

  createdAt: Date,
  updatedAt: Date,
})

const UserModel = model('User', UserSchema, 'users')

export default UserModel
