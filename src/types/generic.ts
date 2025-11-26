export type ObjectWithBuffersAsBase64<T extends Record<string, any>> = {
  [P in keyof T]: T[P] extends Buffer ? string : T[P]
}
