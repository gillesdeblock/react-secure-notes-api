import { Schema, connection } from 'mongoose'

export default connection.model(
  'users',
  new Schema({
    email: String,
    passwordHash: String,

    encryptedMasterKey: String, // base64 ciphertext
    masterKeyIv: String, // base64
    kdfSalt: String, // base64
    kdfIterations: Number,

    createdAt: Date,
    updatedAt: Date,
  }),
)
