import express, { Request, Response } from 'express'
import UserModel from '../models/user'
import useAccessToken from '../middleware/use-access-token'
import { decodeAccessToken } from '../lib/auth'

const router = express.Router()

router.get('/me', useAccessToken(), async function (req: Request, res: Response) {
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
