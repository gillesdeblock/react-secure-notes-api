import crypto from 'crypto'
import argon2 from 'argon2'
import { UserDocument } from '../types'
import { hasProperties } from './utils'

export const encryptPassword = (password: string) => argon2.hash(password)
export const verifyPassword = (passwordHash: string, password: string) => argon2.verify(passwordHash, password)

export function derivePasswordKey(password: string, kdfSalt?: Buffer<ArrayBufferLike>) {
  return argon2.hash(password, {
    salt: kdfSalt,
    raw: true,
    hashLength: 32,
    type: argon2.argon2id,
  })
}

export async function setupUserMasterKeyEncryption(password: string) {
  const kdfSalt = crypto.randomBytes(12)
  const pdk = await derivePasswordKey(password, kdfSalt)

  const masterKey = crypto.randomBytes(32)
  const masterKeyProperties = await encryptMasterKey(masterKey, pdk)

  return {
    kdfSalt,
    masterKey,
    ...masterKeyProperties,
  }
}

export async function decodeUserMasterKey(user: Partial<UserDocument>, password: string) {
  if (!user || !hasProperties(user, 'kdfSalt', 'encryptedMasterKey', 'masterKeyIv', 'masterKeyAuthTag')) {
    throw new Error('unable to decode master key')
  }
  const kdfSalt = Buffer.from(user.kdfSalt, 'base64')
  const masterKeyIv = Buffer.from(user.masterKeyIv, 'base64')
  const masterKeyAuthTag = Buffer.from(user.masterKeyAuthTag, 'base64')
  const encryptedMasterKey = Buffer.from(user.encryptedMasterKey, 'base64')
  const pdk = await derivePasswordKey(password, kdfSalt)
  return (await decryptMasterKey(encryptedMasterKey, pdk, masterKeyAuthTag, masterKeyIv)).toString('base64')
}

export async function encryptMasterKey(masterKey: Buffer, pdk: Buffer) {
  const iv = crypto.randomBytes(12)
  const { encrypted, authTag } = await encryptAesGcm(masterKey, pdk, iv)
  return { encryptedMasterKey: encrypted, masterKeyIv: iv, masterKeyAuthTag: authTag }
}

export async function decryptMasterKey(encryptedMasterKey: Buffer, pdk: Buffer, authTag: Buffer, iv: Buffer) {
  return (await decryptAesGcm(encryptedMasterKey, authTag, pdk, iv)).decrypted
}

export async function encryptAesGcm(plaintext: Buffer, key: crypto.CipherKey, iv: crypto.BinaryLike) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const authTag = cipher.getAuthTag()
  return { encrypted, authTag }
}

export async function decryptAesGcm(encrypted: Buffer, authTag: Buffer, key: crypto.CipherKey, iv: crypto.BinaryLike) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  return { decrypted: Buffer.concat([decipher.update(encrypted), decipher.final()]) }
}
