import express, { Request, Response } from 'express'
import mongoose from 'mongoose'
import cookieParser from 'cookie-parser'
import authRouter from './routes/auth'

const app = express()
app.use(express.json())
app.use(cookieParser())
app.use(authRouter)

const mongoDB = 'mongodb://localhost:27017/secure-notes-api'
mongoose.connect(mongoDB).then(() => {
  app.listen(3000, () => console.log('Server running'))
})

app.get('/', (req: Request, res: Response) => {
  res.json({ message: 'It works!' })
})
