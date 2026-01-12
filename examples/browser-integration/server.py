#!/usr/bin/env python3
"""
Shield Browser Integration Example - Server

Demonstrates how to use BrowserBridge with FastAPI to serve
encrypted API responses that the browser SDK auto-decrypts.

Usage:
    pip install fastapi uvicorn shield-crypto
    python server.py

Then open http://localhost:8000 in your browser.
"""

import base64
import json
import time
import uuid
from typing import Optional

from fastapi import FastAPI, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from shield.integrations import BrowserBridge

# Initialize FastAPI app
app = FastAPI(title="Shield Browser Integration Demo")

# Add CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize BrowserBridge
PASSWORD = "demo-secret-password"
SERVICE = "demo.shield.local"
bridge = BrowserBridge(password=PASSWORD, service=SERVICE)


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the demo HTML page."""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Shield Browser SDK Demo</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
        h1 { color: #333; }
        .card { background: #f5f5f5; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; }
        button { background: #007bff; color: white; border: none; padding: 0.5rem 1rem;
                 border-radius: 4px; cursor: pointer; margin: 0.25rem; }
        button:hover { background: #0056b3; }
        pre { background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 4px;
              overflow-x: auto; font-size: 0.9rem; }
        #log { max-height: 400px; overflow-y: auto; }
    </style>
</head>
<body>
    <h1>Shield Browser SDK Demo</h1>

    <div class="card">
        <h3>Status</h3>
        <p id="status">Not initialized</p>
        <button onclick="initShield()">Initialize Shield</button>
        <button onclick="refreshKey()">Refresh Key</button>
        <button onclick="destroyShield()">Destroy</button>
    </div>

    <div class="card">
        <h3>Test Endpoints</h3>
        <button onclick="fetchSecret()">Fetch Secret Data</button>
        <button onclick="fetchUserProfile()">Fetch User Profile</button>
        <button onclick="fetchUnencrypted()">Fetch Unencrypted</button>
    </div>

    <div class="card">
        <h3>Log</h3>
        <pre id="log"></pre>
    </div>

    <script type="module">
        // Import Shield Browser SDK
        // In production, use: import { ShieldBrowser } from '@guard8/shield-browser';
        // For this demo, we'll use the local build

        const SESSION_ID = 'demo-' + Math.random().toString(36).substr(2, 9);
        let shield = null;

        function log(msg, type = 'info') {
            const logEl = document.getElementById('log');
            const time = new Date().toLocaleTimeString();
            const color = type === 'error' ? '#f5c6cb' : type === 'success' ? '#c3e6cb' : '#d4d4d4';
            logEl.innerHTML += `<span style="color:${color}">[${time}] ${msg}</span>\\n`;
            logEl.scrollTop = logEl.scrollHeight;
        }

        function updateStatus(text, success = true) {
            const statusEl = document.getElementById('status');
            statusEl.textContent = text;
            statusEl.style.color = success ? 'green' : 'red';
        }

        window.initShield = async function() {
            try {
                log('Initializing Shield Browser SDK...');

                // For this demo, we manually fetch the key and decrypt
                // In production with the full SDK:
                // shield = await ShieldBrowser.init(`/api/shield-key?session_id=${SESSION_ID}`);

                const keyResp = await fetch(`/api/shield-key?session_id=${SESSION_ID}`);
                const keyData = await keyResp.json();
                log('Key received: ' + JSON.stringify(keyData, null, 2), 'success');

                // Store key for demo (SDK does this automatically)
                window.sessionKey = keyData;

                updateStatus(`Initialized - Session: ${keyData.session_id}, Expires: ${new Date(keyData.expires_at * 1000).toLocaleTimeString()}`);
                log('Shield initialized successfully!', 'success');
            } catch (err) {
                log('Init error: ' + err.message, 'error');
                updateStatus('Init failed: ' + err.message, false);
            }
        };

        window.refreshKey = async function() {
            await window.initShield();
        };

        window.destroyShield = function() {
            window.sessionKey = null;
            updateStatus('Not initialized');
            log('Shield destroyed');
        };

        window.fetchSecret = async function() {
            if (!window.sessionKey) {
                log('Please initialize Shield first', 'error');
                return;
            }

            try {
                log('Fetching /api/secret...');
                const resp = await fetch(`/api/secret?session_id=${SESSION_ID}`);
                const data = await resp.json();

                log('Raw response: ' + JSON.stringify(data, null, 2));

                if (data.encrypted) {
                    log('Response is encrypted - SDK would auto-decrypt this');
                    log('Encrypted data (base64): ' + data.data.substring(0, 50) + '...');
                }
            } catch (err) {
                log('Fetch error: ' + err.message, 'error');
            }
        };

        window.fetchUserProfile = async function() {
            if (!window.sessionKey) {
                log('Please initialize Shield first', 'error');
                return;
            }

            try {
                log('Fetching /api/user-profile...');
                const resp = await fetch(`/api/user-profile?session_id=${SESSION_ID}`);
                const data = await resp.json();

                log('Raw response: ' + JSON.stringify(data, null, 2));

                if (data.encrypted) {
                    log('Response is encrypted - SDK would auto-decrypt this');
                }
            } catch (err) {
                log('Fetch error: ' + err.message, 'error');
            }
        };

        window.fetchUnencrypted = async function() {
            try {
                log('Fetching /api/public...');
                const resp = await fetch('/api/public');
                const data = await resp.json();

                log('Response (unencrypted): ' + JSON.stringify(data, null, 2), 'success');
            } catch (err) {
                log('Fetch error: ' + err.message, 'error');
            }
        };

        log('Demo loaded. Click "Initialize Shield" to start.');
    </script>
</body>
</html>
"""


@app.get("/api/shield-key")
async def get_shield_key(session_id: str = Query(...)):
    """
    Generate a session key for the browser client.

    In production, validate the session/auth before generating key.
    """
    return bridge.generate_client_key(session_id=session_id, ttl=3600)


@app.get("/api/secret")
async def get_secret(session_id: str = Query(...)):
    """
    Return encrypted secret data.

    The Shield Browser SDK will auto-decrypt this response.
    """
    data = {
        "message": "This is secret data!",
        "timestamp": time.time(),
        "secret_code": "XK-47-ALPHA",
        "access_level": "TOP_SECRET"
    }

    encrypted = bridge.encrypt_for_client(session_id, json.dumps(data).encode())

    return {
        "encrypted": True,
        "data": base64.b64encode(encrypted).decode(),
        "service": SERVICE
    }


@app.get("/api/user-profile")
async def get_user_profile(session_id: str = Query(...)):
    """
    Return encrypted user profile.
    """
    profile = {
        "id": str(uuid.uuid4()),
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "role": "admin",
        "preferences": {
            "theme": "dark",
            "notifications": True
        }
    }

    encrypted = bridge.encrypt_for_client(session_id, json.dumps(profile).encode())

    return {
        "encrypted": True,
        "data": base64.b64encode(encrypted).decode(),
        "service": SERVICE
    }


@app.get("/api/public")
async def get_public():
    """
    Return unencrypted public data.

    The Shield Browser SDK will pass this through unchanged.
    """
    return {
        "message": "This is public data",
        "timestamp": time.time(),
        "version": "1.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    print("Starting Shield Browser Integration Demo...")
    print("Open http://localhost:8000 in your browser")
    uvicorn.run(app, host="0.0.0.0", port=8000)
