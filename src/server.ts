import express, { Request, Response } from 'express'
import mongoose from 'mongoose'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import authRouter from './routes/auth'
import userRouter from './routes/user'
import noteRouter from './routes/note'

const app = express()
app.use(express.json())
app.use(
  cors({
    origin: 'http://localhost:5173',
    credentials: true,
  }),
)
app.use(cookieParser())
app.use(authRouter)
app.use(userRouter)
app.use(noteRouter)

const mongoDB = 'mongodb://localhost:27017/secure-notes-api'
mongoose.connect(mongoDB).then(() => {
  app.listen(3000, () => console.log('Server running'))
})

app.get('/', (req: Request, res: Response) => {
  res.json({ message: 'It works!' })
})
