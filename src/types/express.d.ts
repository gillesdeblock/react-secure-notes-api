import { AccessTokenPayload } from './token'

declare module 'express' {
  interface Request {
    decodedToken?: AccessTokenPayload
  }
}
