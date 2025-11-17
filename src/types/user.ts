export type User = {
  _id: string
  email: string
  passwordHash: string

  encryptedMasterKey: string // base64 ciphertext
  masterKeyIv: string // base64
  kdfSalt: string // base64
  kdfIterations?: number

  createdAt?: string
  updatedAt?: string
}
