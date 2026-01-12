# Shield Browser Integration Example

This example demonstrates how to use Shield's BrowserBridge on the server and the Browser SDK on the client for transparent end-to-end encryption.

## Prerequisites

```bash
pip install fastapi uvicorn shield-crypto
```

## Running

```bash
python server.py
```

Then open http://localhost:8000 in your browser.

## How It Works

### Server Side (Python/FastAPI)

1. **BrowserBridge** generates session-specific encryption keys
2. **Key Endpoint** (`/api/shield-key`) returns the session key to browsers
3. **Protected Endpoints** encrypt responses using `bridge.encrypt_for_client()`

### Client Side (Browser)

1. **ShieldBrowser.init()** fetches the session key
2. **Fetch Hook** intercepts all `fetch()` calls
3. **Auto-Decrypt** detects `{"encrypted": true, ...}` and decrypts transparently

## Files

- `server.py` - FastAPI server with BrowserBridge integration
- `README.md` - This file

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Demo HTML page |
| `GET /api/shield-key?session_id=X` | Get session encryption key |
| `GET /api/secret?session_id=X` | Encrypted secret data |
| `GET /api/user-profile?session_id=X` | Encrypted user profile |
| `GET /api/public` | Unencrypted public data |

## Response Format

Encrypted responses:
```json
{
  "encrypted": true,
  "data": "base64-encoded-ciphertext",
  "service": "demo.shield.local"
}
```

After SDK decryption, your code receives:
```json
{
  "message": "This is secret data!",
  "timestamp": 1704067200,
  ...
}
```
