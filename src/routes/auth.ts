import express from 'express'
import bcrypt from 'bcrypt'
import { status } from 'http-status'
import { UserDocument } from '../types/user'
import UserModel from '../models/user'
import RefreshTokenModel from '../models/refresh-token'
import { createAccessToken, decodeAccessToken, generateRefreshToken } from '../lib/auth'
import { encryptPassword, setupUserMasterKeyEncryption, verifyPassword, decodeUserMasterKey } from '../lib/crypto'
import { hasProperties, sanitizeObjectForDb } from '../lib/utils'

const router = express.Router()
const ONE_WEEK_MS = 1000 * 60 * 60 * 24 * 7

router.post('/auth/login', async function (req, res) {
  const credentials: { email: string; password: string } = req.body

  if (!credentials.email || !credentials.password) {
    res.status(400).send('invalid credentials')
    return
  }

  const user: UserDocument = await UserModel.findOne({
    email: credentials.email,
  })

  if (!user) {
    res.status(404).send('user not found')
    return
  }
  if (!user.passwordHash) {
    console.error(`no passwordHash found for user ${user.email}`)
    res.status(500).send('user incorrectly configured')
    return
  }
  if (!(await verifyPassword(user.passwordHash, credentials.password))) {
    res.status(403).send('invalid credentials')
    return
  }

  if (!hasProperties(user, 'kdfSalt', 'encryptedMasterKey', 'masterKeyIv', 'masterKeyAuthTag')) {
    res.status(500).send('internal server error')
    return
  }

  const now = Date.now()
  const masterKey = await decodeUserMasterKey(user, credentials.password)
  const token = createAccessToken({ userId: user._id, masterKey })
  res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none' })

  await RefreshTokenModel.updateMany({ userId: user._id }, { $set: { revokedAt: new Date(now) } })

  const newHash = await bcrypt.hash(generateRefreshToken(), 10)
  const newRefreshToken = await RefreshTokenModel.create({
    hash: newHash,
    userId: user._id,
    expiresAt: new Date(now + ONE_WEEK_MS),
  })
  res.cookie('refresh_token', newRefreshToken.hash, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
  })

  res.sendStatus(status.NO_CONTENT)
})

router.post('/auth/register', async function (req, res) {
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
  res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none' })

  const refreshTokenHash = await bcrypt.hash(generateRefreshToken(), 10)
  await RefreshTokenModel.create({
    hash: refreshTokenHash,
    userId: result._id,
    expiresAt: new Date(now + ONE_WEEK_MS),
  })
  res.cookie('refresh_token', refreshTokenHash, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
  })

  if (result.errors) {
    res.sendStatus(status.INTERNAL_SERVER_ERROR)
  } else {
    res.sendStatus(status.CREATED)
  }
})

router.post('/auth/logout', async function (req, res) {
  const token = req.cookies.token
  res.clearCookie('token')
  res.clearCookie('refresh_token')

  try {
    const decodedToken = decodeAccessToken(token)
    await RefreshTokenModel.updateMany(
      {
        userId: decodedToken.id,
        $or: [{ revokedAt: { $exists: false } }, { revokedAt: null }],
      },
      { $set: { revokedAt: new Date() } },
    )
    res.sendStatus(status.NO_CONTENT)
  } catch (error) {
    if (error instanceof Error) {
      console.error(error.message)
    }
    res.status(500).send('internal server error')
  }
})

router.post('/auth/refresh', async function (req, res) {
  if (!req.cookies.refresh_token || !req.cookies.token) {
    res.sendStatus(status.UNAUTHORIZED)
    return
  }

  const refreshToken = await RefreshTokenModel.findOne({ hash: req.cookies.refresh_token })

  if (!refreshToken) {
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
    const { userId, masterKey } = decodeAccessToken(req.cookies.token)
    const now = Date.now()

    const newHash = await bcrypt.hash(generateRefreshToken(), 10)
    const newRefreshToken = await RefreshTokenModel.create({
      hash: newHash,
      userId: refreshToken.userId,
      expiresAt: new Date(now + ONE_WEEK_MS),
    })
    res.cookie('refresh_token', newRefreshToken.hash, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
    })

    refreshToken.revokedAt = new Date(now)
    await refreshToken.save()

    const token = createAccessToken({ userId, masterKey })
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none' })

    res.sendStatus(status.NO_CONTENT)
  } catch (error) {
    if (error instanceof Error) {
      console.error(error.message)
    }
    res.status(500).send('internal server error')
  }
})

export default router
