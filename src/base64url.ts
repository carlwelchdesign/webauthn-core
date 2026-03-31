export function encodeBase64Url(value: Buffer | Uint8Array): string {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

export function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4;
  const base64 = padding ? normalized + '='.repeat(4 - padding) : normalized;
  const buffer = Buffer.from(base64, 'base64');
  const bytes = new Uint8Array(new ArrayBuffer(buffer.length));
  bytes.set(buffer);
  return bytes;
}
