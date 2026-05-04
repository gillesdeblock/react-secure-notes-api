import { Request } from 'express'
import { AccessTokenPayload } from './token'

export interface AuthenticatedRequest extends Request {
  decodedToken: AccessTokenPayload
}
