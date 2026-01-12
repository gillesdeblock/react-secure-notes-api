import express, { Request, Response } from 'express'
import crypto from 'crypto'
import useAccessToken from '../middleware/use-access-token'
import { Note, NoteCreatePayload, NoteDocument } from '../types'
import { hasProperties } from '../lib/utils'
import { decryptAesGcm, encryptAesGcm } from '../lib/crypto'
import NoteModel from '../models/note'
import status from 'http-status'
import { sanitizeFilter } from 'mongoose'

const router = express.Router()

router.post('/notes', useAccessToken(), async (req: Request, res: Response) => {
  const payload: NoteCreatePayload = req.body
  const valid = hasProperties(payload, 'title', 'content')

  if (!valid) {
    res.status(400).send('Note is invalid, must have a title and content')
    return
  }

  const { userId, masterKey } = req.decodedToken as NonNullable<express.Request['decodedToken']>
  const now = Date.now()
  const iv = crypto.randomBytes(12)
  const masterKeyBuffer = Buffer.from(masterKey, 'base64')
  const { encrypted: encryptedTitle, authTag: titleAuthTag } = await encryptAesGcm(Buffer.from(payload.title), masterKeyBuffer, iv)
  const { encrypted: encryptedShort, authTag: shortAuthTag } = await encryptAesGcm(Buffer.from(payload.short), masterKeyBuffer, iv)
  const { encrypted: encryptedContent, authTag: contentAuthTag } = await encryptAesGcm(Buffer.from(payload.content), masterKeyBuffer, iv)

  const note: Note = {
    userId,
    tags: payload.tags || [],

    iv: iv.toString('base64'),
    titleAuthTag: titleAuthTag.toString('base64'),
    shortAuthTag: shortAuthTag.toString('base64'),
    contentAuthTag: contentAuthTag.toString('base64'),
    encryptedTitle: encryptedTitle.toString('base64'),
    encryptedShort: encryptedShort.toString('base64'),
    encryptedContent: encryptedContent.toString('base64'),

    createdAt: new Date(now),
    updatedAt: new Date(now),
  }

  const result = await NoteModel.create(note)

  if (result.errors) {
    res.status(500).send('unexpected error')
  } else {
    res.status(203).send({
      id: result._id,
      title: payload.title,
      short: payload.short,
      content: payload.content,
      createdAt: note.createdAt,
      updatedAt: note.updatedAt,
    })
  }
})

router.get('/notes', useAccessToken(), async (req: Request, res: Response) => {
  const { userId, masterKey } = req.decodedToken as NonNullable<typeof req.decodedToken>

  const notes: NoteDocument[] = await NoteModel.find({ userId })
  const decipherKey = Buffer.from(masterKey, 'base64')

  if (!notes?.length) {
    res.send([])
    return
  }

  const bufferize = (base64: string) => Buffer.from(base64, 'base64')

  const decrypt = async (ciphertext: string, authTag: string, iv: string) => {
    const { decrypted } = await decryptAesGcm(bufferize(ciphertext), bufferize(authTag), decipherKey, bufferize(iv))
    return decrypted instanceof Buffer ? decrypted.toString() : null
  }

  const decryptNote = async (note: NoteDocument) => {
    const decryptedNote: {
      id: string | undefined
      title: string | null
      short: string | null
      content: string | null
    } & Partial<NoteDocument> = {
      id: note?._id,
      tags: note?.tags || [],
      title: null,
      short: null,
      content: null,
      createdAt: note?.createdAt,
      updatedAt: note?.updatedAt,
    }

    if (note && hasProperties(note, 'encryptedTitle', 'titleAuthTag', 'iv')) {
      decryptedNote.title = await decrypt(note.encryptedTitle, note.titleAuthTag, note.iv)
    }
    if (note && hasProperties(note, 'encryptedShort', 'shortAuthTag', 'iv')) {
      decryptedNote.short = await decrypt(note.encryptedShort, note.shortAuthTag, note.iv)
    }
    if (note && hasProperties(note, 'encryptedContent', 'contentAuthTag', 'iv')) {
      decryptedNote.content = await decrypt(note.encryptedContent, note.contentAuthTag, note.iv)
    }

    return decryptedNote
  }

  const decryptedNotes = await Promise.all(notes.map(decryptNote))

  res.send(decryptedNotes)
})

router.get('/notes/:id', useAccessToken(), async (req: Request, res: Response) => {
  const { userId, masterKey } = req.decodedToken as NonNullable<typeof req.decodedToken>

  const note: NoteDocument = await NoteModel.findById(req.params.id)

  if (!note) {
    res.sendStatus(404)
    return
  }
  if (note.userId !== userId) {
    res.sendStatus(403)
    return
  }

  const decrypt = async (ciphertext?: string, authTag?: string) => {
    if (!ciphertext || !authTag || !note.iv) {
      return null
    }
    const key = Buffer.from(masterKey, 'base64')
    const iv = Buffer.from(note.iv, 'base64')
    const result = await decryptAesGcm(Buffer.from(ciphertext, 'base64'), Buffer.from(authTag, 'base64'), key, iv)
    return result.decrypted
  }

  const titleDecryption = await decrypt(note.encryptedTitle, note.titleAuthTag)
  const shortDecryption = await decrypt(note.encryptedShort, note.shortAuthTag)
  const contentDecryption = await decrypt(note.encryptedContent, note.contentAuthTag)

  res.send({
    id: note._id,
    tags: note.tags || [],
    title: titleDecryption?.toString(),
    short: shortDecryption?.toString(),
    content: contentDecryption?.toString(),
    createdAt: note.createdAt,
    updatedAt: note.updatedAt,
  })
})

router.put('/notes/:id', useAccessToken(), async (req: Request, res: Response) => {
  const payload: NoteCreatePayload = req.body
  const valid = hasProperties(payload, 'title', 'content')

  if (!valid) {
    res.status(400).send('Note is invalid, must have a title and content')
    return
  }

  const { userId, masterKey } = req.decodedToken as NonNullable<express.Request['decodedToken']>
  const now = Date.now()

  const masterKeyBuffer = Buffer.from(masterKey, 'base64')
  const iv = crypto.randomBytes(12)
  const { encrypted: encryptedTitle, authTag: titleAuthTag } = await encryptAesGcm(Buffer.from(payload.title), masterKeyBuffer, iv)
  const { encrypted: encryptedShort, authTag: shortAuthTag } = await encryptAesGcm(Buffer.from(payload.short), masterKeyBuffer, iv)
  const { encrypted: encryptedContent, authTag: contentAuthTag } = await encryptAesGcm(Buffer.from(payload.content), masterKeyBuffer, iv)

  const result = await NoteModel.findOneAndUpdate({ userId, _id: req.params.id }, {
    iv: iv.toString('base64'),
    titleAuthTag: titleAuthTag.toString('base64'),
    shortAuthTag: shortAuthTag.toString('base64'),
    contentAuthTag: contentAuthTag.toString('base64'),
    encryptedTitle: encryptedTitle.toString('base64'),
    encryptedShort: encryptedShort.toString('base64'),
    encryptedContent: encryptedContent.toString('base64'),
    updatedAt: new Date(now),
  } as Partial<Note>)

  if (!result || result.errors) {
    res.status(500).send('unexpected error')
  } else {
    res.status(203).send({
      id: result._id,
      title: payload.title,
      short: payload.short,
      content: payload.content,
      createdAt: result.createdAt,
      updatedAt: result.updatedAt,
    })
  }
})

router.delete('/notes/:id', useAccessToken(), async (req: Request, res: Response) => {
  const { userId } = req.decodedToken as NonNullable<typeof req.decodedToken>

  const note: NoteDocument = await NoteModel.findById(req.params.id)

  if (!note) {
    res.sendStatus(404)
    return
  }
  if (note.userId !== userId) {
    res.sendStatus(403)
    return
  }

  await NoteModel.deleteOne({ _id: note._id })
  res.sendStatus(status.NO_CONTENT)
})

router.post('/notes/batch-remove', useAccessToken(), async (req: Request, res: Response) => {
  const { userId } = req.decodedToken as NonNullable<typeof req.decodedToken>

  const { deletedCount } = await NoteModel.deleteMany(
    sanitizeFilter({
      userId,
      _id: req.body.ids || [],
    }),
  )

  res.status(status.OK).send({ deleted: deletedCount })
})

export default router
