import express from 'express'
import jwt from 'jsonwebtoken'
import UserModel from '../models/user'
import authenticated from '../middleware/authenticated'

const router = express.Router()

router.get('/me', authenticated, async function (req, res) {
  try {
    const decodedToken = jwt.decode(req.cookies.token, { json: true })

    if (!decodedToken?.id) {
      throw new Error('invalid token')
    }

    const user = await UserModel.findById(decodedToken.id, {
      id: '$_id',
      _id: 0,
      email: 1,
    })

    if (!user) {
      throw new Error('user not found')
    }

    res.send(user)
  } catch (error) {
    if (error) {
      console.error(error.toString())
    }
    res.sendStatus(401)
  }
})

export default router
