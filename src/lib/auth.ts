import jwt, { JwtPayload } from 'jsonwebtoken'
import crypto from 'crypto'
import { hasProperties } from './utils'

interface AccessTokenPayload extends JwtPayload {
  userId: string
  masterKey: string
}

export function createAccessToken(payload: Pick<AccessTokenPayload, 'userId' | 'masterKey'>): string {
  return jwt.sign(payload, 'debug', { expiresIn: 60 * 15 })
}

export function decodeAccessToken(token: string) {
  const decodedToken = jwt.verify(token, 'debug')
  assertAccessTokenPayload(decodedToken)
  return decodedToken
}

export function assertAccessTokenPayload(payload: string | JwtPayload): asserts payload is AccessTokenPayload {
  if (!payload || typeof payload !== 'object' || !hasProperties(payload, 'userId', 'masterKey')) {
    throw new Error('Access token payload is invalid!')
  }
}

export function generateRefreshToken() {
  return crypto.randomBytes(12)
}
