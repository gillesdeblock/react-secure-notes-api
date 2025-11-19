import jwt from 'jsonwebtoken'
import { User } from '../types'

export function createAccessToken(payload: Pick<User, '_id'>): string {
  return jwt.sign({ id: payload._id }, 'debug', { expiresIn: 5 })
}

export function generateRefreshToken() {
  return crypto.randomUUID()
}
