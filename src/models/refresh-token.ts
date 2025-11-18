import { Schema, connection } from 'mongoose'
import { RefreshToken } from '../types/refresh-token'

export default connection.model(
  'refreshtokens',
  new Schema({
    userId: Schema.ObjectId,
    hash: String,
    exp: Number,
    inactive: Boolean,
  }),
)
