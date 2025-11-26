import express from 'express'
import jwt from 'jsonwebtoken'
import UserModel from '../models/user'
import authenticated from '../middleware/authenticated'
import { decodeAccessToken } from '../lib/auth'

const router = express.Router()

router.get('/me', authenticated, async function (req, res) {
  try {
    const decodedToken = decodeAccessToken(req.cookies.token)
    const user = await UserModel.findById(decodedToken.userId)

    if (!user) {
      res.status(401).send('No user found')
      return
    }

    res.send({
      id: user.id,
      email: user.email,
    })
  } catch (error) {
    if (error) {
      console.error(error.toString())
    }
    res.sendStatus(401)
  }
})

export default router
