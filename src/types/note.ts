export type Note = {
  userId: string
  tags: string[]

  iv: string
  titleAuthTag: string
  shortAuthTag: string
  contentAuthTag: string
  encryptedTitle: string
  encryptedShort: string
  encryptedContent: string

  createdAt: Date
  updatedAt: Date
}

export type NoteDocument = (Partial<Note> & { _id: string }) | null

export type NoteCreatePayload = {
  title: string
  short: string
  content: string
  tags: string[]
}
