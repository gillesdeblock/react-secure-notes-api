export type User = {
  _id: string
  email: string
  passwordHash: string

  kdfSalt: string // base64
  masterKeyIv: string // base64
  masterKeyAuthTag: string // base64
  encryptedMasterKey: string // base64 ciphertext

  createdAt?: Date
  updatedAt?: Date
}

export type UserDocument = (Partial<User> & { _id: string }) | null
