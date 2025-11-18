export type RefreshToken = {
  _id: string
  userId: string

  hash: string
  exp?: number
  inactive?: boolean
}
