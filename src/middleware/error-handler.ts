import mongoose from 'mongoose'
import { Request, Response, NextFunction } from 'express'

export default (error: Error & { code?: number; keyValue?: Record<string, unknown> }, _req: Request, res: Response, _next: NextFunction): void => {
  if (error instanceof mongoose.Error.ValidationError) {
    return res.status(400).json({
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
  }
  if (error instanceof mongoose.Error.CastError) {
    return res.status(400).json({ message: `Invalid value for field: ${error.path}` })
  }
  if (error.code === 11000 && error.keyValue) {
    const field = Object.keys(error.keyValue)[0]
    return res.status(409).json({ message: `${field} already exists` })
  }
  res.status(500).json({ message: 'unexpected error' })
}
