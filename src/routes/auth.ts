import express from 'express'
import bcrypt from 'bcrypt'
import UserModel from '../models/user'
import { User } from '../types'
import { createToken } from '../lib/auth'

const router = express.Router()

const encrypt = (value: string) => bcrypt.hash(value, 10)

router.post('/auth/register', async function (req, res) {
  const user: Partial<User & { password: string }> = req.body

  if (!user.password) {
    res.status(400).send('Password is required!')
    return
  }

  // encrypt password
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

  res.header('login', createToken({ ...user }))
  res.send(201)
})

export default router
