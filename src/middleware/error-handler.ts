import mongoose from 'mongoose'
import { Request, Response, NextFunction } from 'express'

export default (error: Error & { code?: number; keyValue?: Record<string, unknown> }, _req: Request, res: Response, _next: NextFunction) => {
  if (error instanceof mongoose.Error.ValidationError) {
    res.status(400).json({
      message: 'Validation error',
      fields: Object.fromEntries(
        Object.entries(error.errors).map(([k, v]) => {
          if (v instanceof mongoose.Error.CastError) {
            return [k, `Invalid value for field: ${v.path}`]
          }
          return [k, v.message]
        }),
      ),
    })
    return
  }
  if (error instanceof mongoose.Error.CastError) {
    res.status(400).json({ message: `Invalid value for field: ${error.path}` })
    return
  }
  if (error.code === 11000 && error.keyValue) {
    const field = Object.keys(error.keyValue)[0]
    res.status(409).json({ message: `${field} already exists` })
    return
  }
  res.status(500).json({ message: 'unexpected error' })
}
