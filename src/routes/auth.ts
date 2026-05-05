import express, { Request, Response } from 'express'
import { UserDocument, AuthenticatedRequest } from '../types'
import UserModel from '../models/user'
import RefreshTokenModel from '../models/refresh-token'
import { createAccessToken, createRefreshToken, DEFAULT_COOKIE_OPTIONS, revokeActiveRefreshTokens, decodeAndGetMasterKeyFromRefreshToken } from '../lib/auth'
import { encryptPassword, setupUserMasterKeyEncryption, verifyPassword, decodeUserMasterKey } from '../lib/crypto'
import { hasProperties, sanitizeObjectForDb } from '../lib/utils'
import useAccessToken from '../middleware/use-access-token'

const router = express.Router()

router.post('/auth/login', async function (req: Request, res: Response) {
  const credentials: { email: string; password: string } = req.body

  if (!credentials.email || !credentials.password) {
    res.status(400).json({ message: 'email and password are required' })
    return
  }

  const user: UserDocument = await UserModel.findOne({
    email: credentials.email,
  })

  if (!user) {
    res.status(401).json({ message: 'invalid credentials' })
    return
  }
  if (!user.passwordHash) {
    console.error(`no passwordHash found for user ${user.email}`)
    res.status(500).json({ message: 'internal server error' })
    return
  }
  if (!(await verifyPassword(user.passwordHash, credentials.password))) {
    res.status(401).json({ message: 'invalid credentials' })
    return
  }

  if (!hasProperties(user, 'kdfSalt', 'encryptedMasterKey', 'masterKeyIv', 'masterKeyAuthTag')) {
    res.status(500).json({ message: 'internal server error' })
    return
  }

  const now = Date.now()
  const userId = user._id.toString()
  await RefreshTokenModel.updateMany({ userId }, { $set: { revokedAt: new Date(now) } })

  const masterKey = await decodeUserMasterKey(user, credentials.password)
  const token = createAccessToken({ userId, masterKey })

  const refreshToken = await createRefreshToken(userId, masterKey, now)
  res.cookie('refresh_token', refreshToken, DEFAULT_COOKIE_OPTIONS)

  res.status(200).json({ accessToken: token })
})

router.post('/auth/register', async function (req: Request, res: Response) {
  const { email, password }: { email: string; password: string } = req.body

  if (!email) {
    res.status(400).json({ message: 'email is required' })
    return
  }
  if (!password) {
    res.status(400).json({ message: 'password is required' })
    return
  }
  if (await UserModel.findOne({ email })) {
    res.status(409).json({ message: 'email already taken' })
    return
  }

  const now = Date.now()
  const passwordHash = await encryptPassword(password)
  const { masterKey, ...encryption } = sanitizeObjectForDb(await setupUserMasterKeyEncryption(password))

  const result = await UserModel.create({
    email,
    passwordHash,
    ...encryption,
    createdAt: new Date(now),
    updatedAt: new Date(now),
  })

  const userId = result._id.toString()
  const token = createAccessToken({ userId, masterKey })

  const refreshToken = await createRefreshToken(userId, masterKey, now)
  res.cookie('refresh_token', refreshToken, DEFAULT_COOKIE_OPTIONS)
  res.status(201).json({ accessToken: token })
})

router.post('/auth/refresh', async function (req: Request, res: Response) {
  const refreshTokenFromCookie = req.cookies.refresh_token
  if (!refreshTokenFromCookie) {
    res.status(401).json({ message: 'refresh_token missing' })
    return
  }

  if (!refreshTokenFromCookie.includes('.')) {
    console.warn('refresh_token does not appear to be a JWT (old format token)')
    res.status(401).json({ message: 'refresh_token invalid' })
    return
  }

  const refreshTokenDoc = await RefreshTokenModel.findOne({ hash: refreshTokenFromCookie })
  if (!refreshTokenDoc || !refreshTokenDoc.userId) {
    console.warn(`unrecognized refresh_token`)
    res.status(401).json({ message: 'refresh_token invalid' })
    return
  }
  if (refreshTokenDoc.expiresAt && refreshTokenDoc.expiresAt < new Date()) {
    console.warn(`expired refresh_token`)
    res.status(401).json({ message: 'refresh_token expired' })
    return
  }
  if (refreshTokenDoc.revokedAt) {
    console.warn(`revoked refresh_token`)
    res.status(401).json({ message: 'refresh_token revoked' })
    return
  }

  let userId: string
  let masterKey: string
  try {
    const decoded = await decodeAndGetMasterKeyFromRefreshToken(refreshTokenFromCookie)
    userId = decoded.userId
    masterKey = decoded.masterKey
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'unknown error'
    console.warn(`failed to decode refresh_token: ${errorMsg}`)
    res.status(401).json({ message: 'refresh_token invalid' })
    return
  }

  const now = Date.now()
  await revokeActiveRefreshTokens(userId)
  const token = createAccessToken({ userId, masterKey })

  const newRefreshToken = await createRefreshToken(userId, masterKey, now)
  res.cookie('refresh_token', newRefreshToken, DEFAULT_COOKIE_OPTIONS)

  res.status(200).json({ accessToken: token })
})

router.post('/auth/logout', useAccessToken(), async function (req: Request, res: Response) {
  const { userId } = (req as AuthenticatedRequest).decodedToken

  res.clearCookie('refresh_token')

  await revokeActiveRefreshTokens(userId)
  res.json({})
})

export default router
