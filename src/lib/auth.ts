import jwt, { JwtPayload } from 'jsonwebtoken'
import { CookieOptions } from 'express'
import crypto from 'crypto'
import { hasProperties } from './utils'
import { AccessTokenPayload } from '../types'
import RefreshTokenModel from '../models/refresh-token'
import { encryptAesGcm, decryptAesGcm } from './crypto'

const ONE_WEEK_MS = 1000 * 60 * 60 * 24 * 7
const REFRESH_TOKEN_ENCRYPTION_KEY_SIZE = 32 // AES-256 requires 32-byte key
const REFRESH_TOKEN_IV_SIZE = 12 // GCM standard IV size

export const DEFAULT_COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: 'none',
}

function getRefreshTokenEncryptionKey(): Buffer {
  return Buffer.from(process.env.JWT_SECRET as string, 'utf-8').subarray(0, REFRESH_TOKEN_ENCRYPTION_KEY_SIZE)
}

export interface RefreshTokenPayload {
  userId: string
  encryptedMasterKey: string
  masterKeyIv: string
  masterKeyAuthTag: string
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

async function encryptMasterKeyForRefreshToken(masterKey: string) {
  const key = getRefreshTokenEncryptionKey()
  const iv = crypto.randomBytes(REFRESH_TOKEN_IV_SIZE)
  const { encrypted, authTag } = await encryptAesGcm(Buffer.from(masterKey, 'base64'), key, iv)
  return {
    encryptedMasterKey: encrypted.toString('base64'),
    masterKeyIv: iv.toString('base64'),
    masterKeyAuthTag: authTag.toString('base64'),
  }
}

async function decryptMasterKeyFromRefreshToken(payload: Pick<RefreshTokenPayload, 'encryptedMasterKey' | 'masterKeyIv' | 'masterKeyAuthTag'>) {
  const key = getRefreshTokenEncryptionKey()
  const encrypted = Buffer.from(payload.encryptedMasterKey, 'base64')
  const iv = Buffer.from(payload.masterKeyIv, 'base64')
  const authTag = Buffer.from(payload.masterKeyAuthTag, 'base64')
  const { decrypted } = await decryptAesGcm(encrypted, authTag, key, iv)
  return decrypted.toString('base64')
}

function assertRefreshTokenPayload(payload: string | JwtPayload): asserts payload is RefreshTokenPayload {
  if (
    !payload ||
    typeof payload !== 'object' ||
    !hasProperties(payload, 'userId', 'encryptedMasterKey', 'masterKeyIv', 'masterKeyAuthTag')
  ) {
    throw new Error('Refresh token payload is invalid!')
  }
}

async function createRefreshTokenJwt(userId: string, masterKey: string): Promise<string> {
  const encrypted = await encryptMasterKeyForRefreshToken(masterKey)
  const payload: RefreshTokenPayload = {
    userId,
    ...encrypted,
  }
  return jwt.sign(payload, process.env.JWT_SECRET as string, { noTimestamp: true })
}

function decodeRefreshTokenJwt(token: string): RefreshTokenPayload {
  const decodedToken = jwt.verify(token, process.env.JWT_SECRET as string)
  assertRefreshTokenPayload(decodedToken)
  return decodedToken
}

export async function decodeAndGetMasterKeyFromRefreshToken(
  token: string,
): Promise<{ userId: string; masterKey: string }> {
  const payload = decodeRefreshTokenJwt(token)
  const masterKey = await decryptMasterKeyFromRefreshToken(payload)
  return { userId: payload.userId, masterKey }
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

export async function createRefreshToken(userId: string, masterKey: string, date: Date | number = Date.now()) {
  const time = date instanceof Date ? date.getTime() : date
  const token = await createRefreshTokenJwt(userId, masterKey)
  await RefreshTokenModel.create({
    userId,
    hash: token,
    expiresAt: new Date(time + ONE_WEEK_MS),
  })
  return token
}
