import { Request, Response, NextFunction } from 'express'
import jwt, { JsonWebTokenError } from 'jsonwebtoken'
import status from 'http-status'

export default function authenticated(req: Request, res: Response, next: NextFunction) {
  let { authorization } = req.headers

  if (!authorization && typeof req.cookies.token === 'string') {
    authorization = req.cookies.token
  } else if (!authorization) {
    res.status(status.UNAUTHORIZED).send('unauthorized')
    return
  }

  try {
    const token = authorization.replace('Bearer ', '')
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
