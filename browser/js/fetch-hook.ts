/**
 * Fetch Interceptor for Shield Browser SDK
 *
 * Monkey-patches window.fetch to automatically decrypt Shield-encrypted responses.
 */

import type { ShieldClient as WasmClient } from '../pkg/shield_browser.js';
import type { EncryptedEnvelope } from './types.js';

let originalFetch: typeof fetch | null = null;
let isInstalled = false;

/**
 * Install the fetch interceptor.
 *
 * @param client - WASM ShieldClient instance
 * @param encryptedIndicator - JSON field indicating encryption (default: 'encrypted')
 * @param onError - Error handler callback
 */
export function installFetchHook(
  client: WasmClient,
  encryptedIndicator: string = 'encrypted',
  onError?: (error: Error, response: Response) => void
): void {
  if (isInstalled) {
    console.warn('Shield fetch hook already installed');
    return;
  }

  if (typeof window === 'undefined' || typeof window.fetch !== 'function') {
    console.warn('Shield fetch hook requires browser environment');
    return;
  }

  originalFetch = window.fetch;

  window.fetch = async function shieldFetch(
    input: RequestInfo | URL,
    init?: RequestInit
  ): Promise<Response> {
    // Call original fetch
    const response = await originalFetch!.call(window, input, init);

    // Only process JSON responses
    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      return response;
    }

    // Clone response to read body (can only be read once)
    const clonedResponse = response.clone();

    try {
      const text = await clonedResponse.text();

      // Try to parse as JSON
      let data: unknown;
      try {
        data = JSON.parse(text);
      } catch {
        // Not valid JSON, return original
        return response;
      }

      // Check if it's an encrypted envelope
      if (!isEncryptedEnvelope(data, encryptedIndicator)) {
        return response;
      }

      // Check if client has valid key. Fail closed: a recognized encrypted
      // envelope must never reach the application as if it were plain data.
      if (!client.isValid()) {
        console.warn('Shield: Key expired or not set, failing closed');
        return shieldErrorResponse();
      }

      // Decrypt the envelope. On failure return an error Response instead
      // of the still-encrypted envelope, so response.json() consumers get
      // an explicit error rather than ciphertext masquerading as data.
      let decryptedText: string;
      try {
        decryptedText = client.decryptEnvelope(text);
      } catch (error) {
        if (onError) {
          onError(error as Error, response);
        } else {
          console.error('Shield decryption error:', error);
        }
        return shieldErrorResponse();
      }

      // Create new response with decrypted body
      return new Response(decryptedText, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    } catch (error) {
      if (onError) {
        onError(error as Error, response);
      } else {
        console.error('Shield decryption error:', error);
      }
      return shieldErrorResponse();
    }
  };

  isInstalled = true;
}

/**
 * Uninstall the fetch interceptor (restore original fetch).
 */
export function uninstallFetchHook(): void {
  if (!isInstalled || !originalFetch) {
    return;
  }

  window.fetch = originalFetch;
  originalFetch = null;
  isInstalled = false;
}

/**
 * Check if fetch hook is currently installed.
 */
export function isFetchHookInstalled(): boolean {
  return isInstalled;
}

/**
 * Fail-closed error response returned when a recognized encrypted envelope
 * cannot be decrypted (missing/expired key or decryption failure).
 */
function shieldErrorResponse(): Response {
  return new Response(JSON.stringify({ error: 'Shield decryption failed' }), {
    status: 502,
    statusText: 'Shield Decryption Failed',
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * Type guard for encrypted envelope.
 */
function isEncryptedEnvelope(
  data: unknown,
  indicator: string
): data is EncryptedEnvelope {
  if (typeof data !== 'object' || data === null) {
    return false;
  }
  const obj = data as Record<string, unknown>;
  return obj[indicator] === true && typeof obj['data'] === 'string';
}
