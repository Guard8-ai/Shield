// Stub for WASM module - replaced by vi.mock in tests
export class ShieldClient {
  setKey() {}
  decrypt() { return new Uint8Array(); }
  decryptEnvelope() { return ''; }
  isValid() { return false; }
  getSessionId() { return ''; }
  getExpiresAt() { return BigInt(0); }
  clear() {}
}

export default function init() { return Promise.resolve(); }
