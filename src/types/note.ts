export type Note = {
  _id: string
  userId: string

  encryptedTitle: string // base64
  encryptedContent: string // base64
  iv: string // base64

  // plaintext metadata
  updatedAt: string
  createdAt: string
  tags: string[] // encrypted or not (design choice)

  version: number // for conflict resolution
}
