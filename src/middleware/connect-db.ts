import { Request, Response, NextFunction } from 'express'
import { connectDB } from '../lib/mongoose'

export default async (req: Request, res: Response, next: NextFunction) => {
  try {
    await connectDB()
    next()
  } catch (err) {
    next(err)
  }
}
