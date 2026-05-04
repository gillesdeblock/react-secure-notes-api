import express, { Request, Response } from 'express'
import UserModel from '../models/user'
import useAccessToken from '../middleware/use-access-token'
import { AuthenticatedRequest } from '../types'

const router = express.Router()

router.get('/me', useAccessToken(), async function (req: Request, res: Response) {
  const { userId } = (req as AuthenticatedRequest).decodedToken
  const user = await UserModel.findById(userId)

  if (!user) {
    res.status(404).json({ message: 'user not found' })
    return
  }

  res.json({
    id: user.id,
    email: user.email,
  })
})

export default router
