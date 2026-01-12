import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import authRouter from './routes/auth'
import userRouter from './routes/user'
import noteRouter from './routes/note'
import connectDb from './middleware/connect-db'

const app = express()

app.use(
  cors({
    origin: (origin, callback) => {
      const allowed = ['https://secure-notes.gillesdeblock.com', 'http://localhost:5173']
      if (!origin || allowed.includes(origin)) {
        callback(null, true)
      } else {
        callback(new Error('Not allowed by CORS'))
      }
    },
    credentials: true,
  }),
)

app.use(express.json())
app.use(cookieParser())
app.use(authRouter)
app.use(userRouter)
app.use(noteRouter)
app.use(connectDb)

app.get('/health', (req, res) => {
  res.json({ ok: true })
})

export default app
