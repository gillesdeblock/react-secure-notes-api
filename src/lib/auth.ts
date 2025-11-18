import jwt, { type JwtPayload } from 'jsonwebtoken'

export function createAccessToken(payload: Partial<JwtPayload>): string {
  return jwt.sign({ ...payload }, 'debug', {
    expiresIn: 60 * 5,
  })
}

export function generateRefreshToken() {
  return crypto.randomUUID()
}
