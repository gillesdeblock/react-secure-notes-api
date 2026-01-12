import express, { Request, Response } from 'express'
import { status } from 'http-status'
import { UserDocument } from '../types/user'
import UserModel from '../models/user'
import RefreshTokenModel from '../models/refresh-token'
import { createAccessToken, createRefreshToken, decodeAccessToken, DEFAULT_COOKIE_OPTIONS, revokeActiveRefreshTokens } from '../lib/auth'
import { encryptPassword, setupUserMasterKeyEncryption, verifyPassword, decodeUserMasterKey } from '../lib/crypto'
import { hasProperties, sanitizeObjectForDb } from '../lib/utils'
import useAccessToken from '../middleware/use-access-token'

const router = express.Router()

router.post('/auth/login', async function (req: Request, res: Response) {
  const credentials: { email: string; password: string } = req.body

  if (!credentials.email || !credentials.password) {
    res.status(400).send({ message: 'invalid credentials' })
    return
  }

  const user: UserDocument = await UserModel.findOne({
    email: credentials.email,
  })

  if (!user) {
    res.status(404).send({ message: 'user not found' })
    return
  }
  if (!user.passwordHash) {
    console.error(`no passwordHash found for user ${user.email}`)
    res.status(500).send({ message: 'user incorrectly configured' })
    return
  }
  if (!(await verifyPassword(user.passwordHash, credentials.password))) {
    res.status(403).send({ message: 'invalid credentials' })
    return
  }

  if (!hasProperties(user, 'kdfSalt', 'encryptedMasterKey', 'masterKeyIv', 'masterKeyAuthTag')) {
    res.status(500).send({ message: 'internal server error' })
    return
  }

  const now = Date.now()
  await RefreshTokenModel.updateMany({ userId: user._id }, { $set: { revokedAt: new Date(now) } })

  const masterKey = await decodeUserMasterKey(user, credentials.password)
  const token = createAccessToken({ userId: user._id, masterKey })
  res.cookie('token', token, DEFAULT_COOKIE_OPTIONS)

  const refreshToken = await createRefreshToken(user._id, now)
  res.cookie('refresh_token', refreshToken.hash, DEFAULT_COOKIE_OPTIONS)

  res.sendStatus(status.NO_CONTENT)
})

router.post('/auth/register', async function (req: Request, res: Response) {
  const { email, password }: { email: string; password: string } = req.body

  if (!email) {
    res.status(400).send('Email is required!')
    return
  }
  if (!password) {
    res.status(400).send('Password is required!')
    return
  }
  if (await UserModel.findOne({ email })) {
    res.status(400).send('Email is already taken')
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

  const token = createAccessToken({ userId: result._id.toString(), masterKey })
  res.cookie('token', token, DEFAULT_COOKIE_OPTIONS)

  const refreshToken = await createRefreshToken(result._id.toString(), new Date(now))
  res.cookie('refresh_token', refreshToken.hash, DEFAULT_COOKIE_OPTIONS)

  if (result.errors) {
    res.sendStatus(status.INTERNAL_SERVER_ERROR)
  } else {
    res.sendStatus(status.CREATED)
  }
})

router.post('/auth/refresh', useAccessToken({ ignoreExpiration: true }), async function (req: Request, res: Response) {
  const refreshToken = await RefreshTokenModel.findOne({ hash: req.cookies.refresh_token })

  if (!refreshToken || !refreshToken.userId) {
    console.warn(`unrecognized refresh_token ${req.cookies.refresh_token}`)
    res.sendStatus(status.UNAUTHORIZED)
    return
  }
  if (refreshToken.expiresAt && refreshToken.expiresAt < new Date()) {
    console.warn(`expired refresh_token ${req.cookies.refresh_token}`)
    res.sendStatus(status.UNAUTHORIZED)
    return
  }
  if (refreshToken.revokedAt) {
    console.warn(`revoked refresh_token ${req.cookies.refresh_token}`)
    res.sendStatus(status.UNAUTHORIZED)
    return
  }

  try {
    const now = Date.now()
    const { userId, masterKey } = req.decodedToken as NonNullable<Request['decodedToken']>
    await revokeActiveRefreshTokens(userId)

    const token = createAccessToken({ userId, masterKey })
    res.cookie('token', token, DEFAULT_COOKIE_OPTIONS)

    const newRefreshToken = await createRefreshToken(userId, now)
    res.cookie('refresh_token', newRefreshToken.hash, DEFAULT_COOKIE_OPTIONS)

    res.sendStatus(status.NO_CONTENT)
  } catch (error) {
    if (error instanceof Error) {
      console.error(error.message)
    }
    res.status(500).send({ message: 'internal server error' })
  }
})

router.post('/auth/logout', async function (req: Request, res: Response) {
  const token = req.cookies.token
  res.clearCookie('token')
  res.clearCookie('refresh_token')

  try {
    const { userId } = decodeAccessToken(token)
    await revokeActiveRefreshTokens(userId)
    res.sendStatus(status.NO_CONTENT)
  } catch (error) {
    if (error instanceof Error) {
      console.error(error.message)
    }
    res.status(500).send({ message: 'internal server error' })
  }
})

export default router
