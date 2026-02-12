import jwt, { JwtPayload } from 'jsonwebtoken'
import { CookieOptions } from 'express'
import bcrypt from 'bcrypt'
import crypto from 'crypto'
import { hasProperties } from './utils'
import { AccessTokenPayload } from '../types'
import RefreshTokenModel from '../models/refresh-token'

const ONE_WEEK_MS = 1000 * 60 * 60 * 24 * 7

export const DEFAULT_COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: 'none',
}

export function createAccessToken(payload: Pick<AccessTokenPayload, 'userId' | 'masterKey'>, expiresIn = 900): string {
  return jwt.sign(payload, process.env.JWT_SECRET as string, { expiresIn })
}

export function decodeAccessToken(token: string) {
  const decodedToken = jwt.verify(token, process.env.JWT_SECRET as string)
  assertAccessTokenPayload(decodedToken)
  return decodedToken
}

export function assertAccessTokenPayload(payload: string | JwtPayload): asserts payload is AccessTokenPayload {
  if (!payload || typeof payload !== 'object' || !hasProperties(payload, 'userId', 'masterKey')) {
    throw new Error('Access token payload is invalid!')
  }
}

export function generateRefreshTokenHash(saltOrRounds: string | number = 10) {
  return bcrypt.hash(crypto.randomBytes(12), saltOrRounds)
}

export async function revokeActiveRefreshTokens(userId: string) {
  return RefreshTokenModel.updateMany(
    {
      userId,
      $or: [{ revokedAt: { $exists: false } }, { revokedAt: null }],
    },
    { $set: { revokedAt: new Date() } },
  )
}

export async function createRefreshToken(userId: string, date: Date | number = Date.now()) {
  const time = date instanceof Date ? date.getTime() : date
  const hash = await generateRefreshTokenHash()
  return RefreshTokenModel.create({
    userId,
    hash,
    expiresAt: new Date(time + ONE_WEEK_MS),
  })
}
