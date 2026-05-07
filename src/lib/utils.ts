type ObjectWithBuffersAsBase64<T extends Record<string, unknown>> = {
  [P in keyof T]: T[P] extends Buffer ? string : T[P]
}

export function hasProperties<T extends Record<string, unknown>, K extends PropertyKey>(
  obj: T,
  ...props: K[]
): obj is T & Record<K, NonNullable<unknown>> {
  return props.every((prop) => obj[prop as keyof T] !== undefined)
}

export function sanitizeObjectForDb<T extends Record<string, unknown>>(obj: T): ObjectWithBuffersAsBase64<T> {
  return Object.fromEntries(
    Object.entries(obj).map(([key, value]) => [key, value instanceof Buffer ? value.toString('base64') : value]),
  ) as ObjectWithBuffersAsBase64<T>
}
