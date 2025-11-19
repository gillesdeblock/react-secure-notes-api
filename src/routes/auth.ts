import express from 'express'
import bcrypt from 'bcrypt'
import { status } from 'http-status'
import UserModel from '../models/user'
import RefreshTokenModel from '../models/refresh-token'
import { User } from '../types'
import { createAccessToken, generateRefreshToken } from '../lib/auth'

const router = express.Router()
const ONE_WEEK_MS = 1000 * 60 * 60 * 24 * 7

const encrypt = (value: string) => bcrypt.hash(value, 10)

router.post('/auth/login', async function (req, res) {
  const credentials: { email: string; password: string } = req.body

  if (!credentials.email || !credentials.password) {
    res.status(400).send('invalid credentials')
    return
  }

  const user = await UserModel.findOne({ email: credentials.email })
  if (!user) {
    res.status(404).send('user not found')
    return
  }

  const result = await bcrypt.compare(credentials.password, user.passwordHash)

  if (!result) {
    res.status(403).send('incorrrect password')
    return
  }

  const token = createAccessToken(user)
  res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none' })

  await RefreshTokenModel.updateMany({ userId: user.id }, { $set: { revokedAt: new Date() } })

  const newHash = await encrypt(generateRefreshToken())
  const newRefreshToken = await RefreshTokenModel.create({
    hash: newHash,
    userId: user.id,
    expiresAt: new Date(Date.now() + ONE_WEEK_MS),
  })
  res.cookie('refresh_token', newRefreshToken.hash, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
  })

  res.sendStatus(status.NO_CONTENT)
})

router.post('/auth/register', async function (req, res) {
  const user: Partial<User & { password: string }> = req.body

  if (!user.password) {
    res.status(400).send('Password is required!')
    return
  }
  if (await UserModel.findOne({ email: user.email })) {
    res.status(400).send('Email is already taken')
    return
  }

  user.passwordHash = await encrypt(user.password)
  delete user.password

  const result = await UserModel.create(user)

  if (result.errors) {
    res.send(500)
  } else {
    res.send(201)
  }
})

router.post('/auth/refresh', async function (req, res) {
  if (!req.cookies.refresh_token) {
    res.sendStatus(status.UNAUTHORIZED).end()
    return
  }

  const refreshToken = await RefreshTokenModel.findOne({ hash: req.cookies.refresh_token })

  if (!refreshToken) {
    console.warn(`unrecognized refresh_token ${req.cookies.refresh_token}`)
    res.sendStatus(status.UNAUTHORIZED).end()
    return
  }

  if (refreshToken.expiresAt && refreshToken.expiresAt < new Date()) {
    console.warn(`expired refresh_token ${req.cookies.refresh_token}`)
    res.sendStatus(status.UNAUTHORIZED).end()
    return
  }
  if (refreshToken.revokedAt) {
    console.warn(`revoked refresh_token ${req.cookies.refresh_token}`)
    res.sendStatus(status.UNAUTHORIZED).end()
    return
  }

  const newHash = await encrypt(generateRefreshToken())
  const newRefreshToken = await RefreshTokenModel.create({
    hash: newHash,
    userId: refreshToken.userId,
    expiresAt: new Date(Date.now() + ONE_WEEK_MS),
  })
  res.cookie('refresh_token', newRefreshToken.hash, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
  })

  refreshToken.revokedAt = new Date()
  await refreshToken.save()

  const token = createAccessToken({ _id: newRefreshToken.userId })
  res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none' })

  res.sendStatus(status.NO_CONTENT).end()
})

export default router
