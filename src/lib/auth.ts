import jwt, { type JwtPayload } from 'jsonwebtoken'

export function createToken(payload: JwtPayload): string {
  return jwt.sign(payload, 'debug', {
    expiresIn: 60 * 5,
  })
}
