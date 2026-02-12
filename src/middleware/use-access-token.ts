import { Request, Response, NextFunction } from 'express'
import jwt, { JsonWebTokenError } from 'jsonwebtoken'
import status from 'http-status'
import { assertAccessTokenPayload } from '../lib/auth'

export default (verifyOptions?: jwt.VerifyOptions) => (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.cookies.token) {
      res.status(status.UNAUTHORIZED).send({ message: 'unauthorized' })
      return
    }
    const payload = jwt.verify(req.cookies.token, process.env.JWT_SECRET as string, verifyOptions)
    assertAccessTokenPayload(payload)
    req.decodedToken = payload
    next()
  } catch (e: unknown | JsonWebTokenError) {
    if (!(e instanceof JsonWebTokenError)) {
      res.status(status.UNAUTHORIZED).send({ message: 'authentication failed' })
      return
    }
    res.status(status.UNAUTHORIZED).send({ message: e.message })
    return
  }
}
