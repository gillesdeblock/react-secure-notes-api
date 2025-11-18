import express, { type Response } from 'express'
import bcrypt from 'bcrypt'
import mongoose from 'mongoose'
import jwt from 'jsonwebtoken'
import { status } from 'http-status'
import UserModel from '../models/user'
import RefreshTokenModel from '../models/refresh-token'
import { User } from '../types'
import { createAccessToken, generateRefreshToken } from '../lib/auth'
import authenticated from '../middleware/authenticated'
import { RefreshToken } from '../types/refresh-token'

const router = express.Router()

const ONE_WEEK_MS = 1000 * 60 * 60 * 24 * 7

const ObjectId = mongoose.Types.ObjectId
const encrypt = (value: string) => bcrypt.hash(value, 10)

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

  const result = await bcrypt.compare(credentials.password, user.passwordHash as string)

  if (!result) {
    res.status(403).send('incorrrect password')
    return
  }

  const token = createAccessToken(user)
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', secure: true })

  const { hash } = await renewRefreshToken(new ObjectId(user._id))
  res.cookie('refresh_token', hash, {
    httpOnly: true,
    sameSite: 'strict',
    secure: true,
  })

  res.send(status.NO_CONTENT)
})

router.post('/auth/refresh', authenticated, async function (req, res) {
  const decodedToken = jwt.decode(req.cookies.token, { json: true })
  const userId = new ObjectId(decodedToken?._doc._id as string)
  const user = await UserModel.findOne({ _id: userId })

  if (!user) {
    res.status(status.NOT_FOUND).send('user not found')
    return
  }
  if (!req.cookies.refresh_token) {
    res.status(status.BAD_REQUEST).send('no refresh token provided')
    return
  }
  const refreshToken = await RefreshTokenModel.findOne({ hash: req.cookies['refresh_token'] })
  if (!refreshToken) {
    res.status(status.NOT_FOUND).send('refresh token not found')
    return
  }
  if (refreshToken.inactive) {
    res.status(status.UNAUTHORIZED).send('refresh token expired')
    return
  }

  const token = createAccessToken(user)
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', secure: true })

  const { hash } = await renewRefreshToken(userId)
  res.cookie('refresh_token', hash, {
    httpOnly: true,
    sameSite: 'strict',
    secure: true,
  })

  res.sendStatus(status.NO_CONTENT)
})

async function renewRefreshToken(userId: mongoose.Types.ObjectId) {
  const hash = await encrypt(generateRefreshToken())

  const refreshToken = await RefreshTokenModel.create({
    hash,
    exp: new Date().getTime() + ONE_WEEK_MS,
    userId,
    inactive: false,
  })

  // disable any other refresh tokens for this user
  await RefreshTokenModel.updateMany(
    { _id: { $ne: new ObjectId(refreshToken._id) }, userId },
    { $set: { inactive: true } },
  )

  return refreshToken
}

export default router
