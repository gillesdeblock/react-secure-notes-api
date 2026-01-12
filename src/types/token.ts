export type RefreshToken = {
  _id: string
  userId: string
  hash: string
  expiresAt?: Date
  revokedAt?: Date
}

export type AccessTokenPayload = {
  userId: string
  masterKey: string
}
