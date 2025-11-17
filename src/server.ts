import express, { Request, Response } from 'express'

const app = express()
app.use(express.json())

app.get('/api/hello', (req: Request, res: Response) => {
  res.json({ message: 'Hello world' })
})

app.listen(3000, () => console.log('Server running'))
