export const b64urlToBytes = (input: string): Uint8Array => {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const binary = atob(normalized + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
};

export const base64ToBytes = (input: string): Uint8Array => {
  const trimmed = input.replace(/\s+/g, "");
  if (/^[\w+/=-]+$/.test(trimmed)) return b64urlToBytes(trimmed);
  throw new TypeError("value is not valid base64");
};

export const utf8 = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

export const bytesToUtf8 = (input: string): Uint8Array => new TextEncoder().encode(input);

export const toHex = (bytes: Uint8Array): string => {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
};

export const toBase64 = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
};
