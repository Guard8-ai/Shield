# @guard8/shield-browser

Shield Browser SDK - Transparent auto-decryption for web applications.

## Installation

```bash
npm install @guard8/shield-browser
```

Or via CDN:

```html
<script src="https://unpkg.com/@guard8/shield-browser"></script>
```

## Quick Start

```javascript
import { ShieldBrowser } from '@guard8/shield-browser';

// Initialize (fetches key and installs fetch hook)
await ShieldBrowser.init('/api/shield-key');

// All fetch() calls now auto-decrypt!
const data = await fetch('/api/secret').then(r => r.json());
// data is already decrypted - no manual intervention needed
```

## How It Works

1. **Initialization**: `ShieldBrowser.init()` fetches a session key from your server's `BrowserBridge` endpoint
2. **Fetch Interception**: The SDK monkey-patches `window.fetch` to intercept responses
3. **Auto-Detection**: JSON responses with `{"encrypted": true, "data": "..."}` are automatically detected
4. **Transparent Decryption**: Encrypted responses are decrypted before returning to your application code

## Server Setup (Python)

```python
from fastapi import FastAPI, Depends
from shield.integrations import BrowserBridge

app = FastAPI()
bridge = BrowserBridge(password="your-secret", service="api.example.com")

@app.get("/api/shield-key")
async def get_shield_key(session_id: str):
    return bridge.generate_client_key(session_id)

@app.get("/api/secret")
async def get_secret(session_id: str):
    data = {"message": "This is secret!", "user_id": 123}
    encrypted = bridge.encrypt_for_client(
        session_id,
        json.dumps(data).encode()
    )
    return {
        "encrypted": True,
        "data": base64.b64encode(encrypted).decode()
    }
```

## Configuration

```javascript
await ShieldBrowser.init('/api/shield-key', {
  // Seconds before expiry to auto-refresh key (default: 60)
  keyRefreshMargin: 120,

  // Whether to auto-refresh expired keys (default: true)
  autoRefresh: true,

  // Whether to intercept fetch() calls (default: true)
  interceptFetch: true,

  // JSON field indicating encrypted payload (default: 'encrypted')
  encryptedIndicator: 'encrypted',

  // Callback when key is refreshed
  onKeyRefresh: (session) => {
    console.log('Key refreshed:', session.sessionId);
  },

  // Callback when decryption fails
  onDecryptError: (error, response) => {
    console.error('Decryption failed:', error);
  },

  // Additional headers for key endpoint
  keyEndpointHeaders: {
    'Authorization': 'Bearer token123'
  }
});
```

## API Reference

### ShieldBrowser

#### Static Methods

```typescript
// Initialize the SDK
static async init(keyEndpoint: string, config?: ShieldClientConfig): Promise<ShieldBrowser>

// Get current instance (throws if not initialized)
static getInstance(): ShieldBrowser

// Check if initialized
static isInitialized(): boolean
```

#### Instance Methods

```typescript
// Refresh session key manually
async refreshKey(): Promise<SessionInfo>

// Manual decryption (for non-fetch use cases)
decrypt(encryptedBase64: string): Uint8Array

// Decrypt JSON envelope
decryptEnvelope(envelopeJson: string): string

// Check if key is valid
isKeyValid(): boolean

// Get current session info
getSession(): SessionInfo | null

// Cleanup and restore original fetch
destroy(): void
```

## Manual Decryption

For cases where you don't want automatic fetch interception:

```javascript
await ShieldBrowser.init('/api/shield-key', { interceptFetch: false });

const client = ShieldBrowser.getInstance();
const response = await fetch('/api/secret');
const envelope = await response.json();

if (envelope.encrypted) {
  const decrypted = client.decryptEnvelope(JSON.stringify(envelope));
  const data = JSON.parse(decrypted);
}
```

## Browser Support

- Chrome 80+
- Firefox 75+
- Safari 14+
- Edge 80+

Requires WebAssembly support.

## Security Notes

- Session keys are stored in memory only (not localStorage)
- Keys auto-expire based on server-set TTL
- All decryption happens client-side via WASM
- No plaintext ever sent over the network

## License

MIT License - See [LICENSE](../LICENSE)
