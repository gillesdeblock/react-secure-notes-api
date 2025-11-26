import { ObjectWithBuffersAsBase64 } from '../types'

export function hasProperties<T extends Record<string, any>, K extends PropertyKey>(
  obj: T,
  ...props: K[]
): obj is T & Record<K, NonNullable<any>> {
  return props.every((prop) => obj[prop as keyof T] !== undefined)
}

export function sanitizeObjectForDb<T extends Record<string, any>>(obj: T): ObjectWithBuffersAsBase64<T> {
  return Object.fromEntries(
    Object.entries(obj).map(([key, value]) => [key, value instanceof Buffer ? value.toString('base64') : value]),
  ) as ObjectWithBuffersAsBase64<T>
}
