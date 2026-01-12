import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import authRouter from './routes/auth'
import userRouter from './routes/user'
import noteRouter from './routes/note'
import connectDb from './middleware/connect-db'

const app = express()

app.use(express.json())
app.use(cookieParser())
app.use(authRouter)
app.use(userRouter)
app.use(noteRouter)
app.use(
  cors({
    origin: 'https://secure-notes.gillesdeblock.com',
    credentials: true,
  }),
)
app.use(connectDb)

console.log(process.env)

app.get('/health', (req, res) => {
  res.json({ ok: true })
})

export default app
