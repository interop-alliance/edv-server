declare module 'base58-universal' {
  export function encode(input: Uint8Array, maxline?: number): string
  export function decode(input: string): Uint8Array
}

// the package ships types at types/index.d.ts but its `exports` map does
// not expose them
declare module '@interop/http-digest-header' {
  export function createHeaderValue(options: {
    data: string | object | Uint8Array
    algorithm?: string
    useMultihash?: boolean
  }): Promise<string>
  export function verifyHeaderValue(options: {
    data: string | object | Uint8Array
    headerValue: string
  }): Promise<{ verified: boolean; error?: Error }>
}
