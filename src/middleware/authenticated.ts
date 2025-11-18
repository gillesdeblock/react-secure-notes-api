import { Request, Response, NextFunction } from 'express'
import jwt, { JsonWebTokenError } from 'jsonwebtoken'
import status from 'http-status'

export default function authenticated(req: Request, res: Response, next: NextFunction) {
  // const { authorization } = req.headers
  const token = req.cookies.token

  if (!token) {
    res.status(status.FORBIDDEN).send('unauthorized')
    return
  }

  try {
    // const token = token.replace('Bearer ', '')
    jwt.verify(token, 'debug')
    next()
  } catch (e: unknown | JsonWebTokenError) {
    if (!(e instanceof JsonWebTokenError)) {
      res.status(status.UNAUTHORIZED).send('authentication failed')
      return
    }
    res.status(status.UNAUTHORIZED).send(e.message)

    return
  }
}
