import { Request, Response, NextFunction } from 'express'
import { connectDB } from '../lib/mongoose'

export default async (req: Request, res: Response, next: NextFunction) => {
  try {
    const uri = process.env.MONGO_URI as string
    await connectDB(uri)
    next()
  } catch (err) {
    next(err)
  }
}
