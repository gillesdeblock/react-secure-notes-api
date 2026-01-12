import mongoose from 'mongoose'

let cached = global.mongoose

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null }
}

export async function connectDB(uri: string = 'mongodb+srv://gillesdeblock_db_user:89l0yhaBLJDgokgb@cluster0.id3onim.mongodb.net/') {
  if (cached.conn) return cached.conn

  if (!cached.promise) {
    cached.promise = mongoose.connect(uri).then((m) => m)
  }

  cached.conn = await cached.promise
  return cached.conn
}
