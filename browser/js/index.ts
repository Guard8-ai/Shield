/**
 * Shield Browser SDK
 *
 * Provides transparent auto-decryption of Shield-encrypted API responses.
 *
 * @example
 * ```javascript
 * import { ShieldBrowser } from '@guard8/shield-browser';
 *
 * // Initialize (fetches key and installs fetch hook)
 * await ShieldBrowser.init('/api/shield-key');
 *
 * // All fetch() calls now auto-decrypt
 * const data = await fetch('/api/secret').then(r => r.json());
 * // data is already decrypted!
 * ```
 */

// @ts-ignore - WASM module will be available after build
import init, { ShieldClient as WasmClient } from '../pkg/shield_browser.js';
import { installFetchHook, uninstallFetchHook, isFetchHookInstalled } from './fetch-hook.js';
import type { ShieldClientConfig, SessionInfo, KeyResponse } from './types.js';

export type { ShieldClientConfig, SessionInfo, KeyResponse, EncryptedEnvelope } from './types.js';

let wasmInitialized = false;

/**
 * Main Shield Browser SDK class.
 *
 * Singleton pattern - use `ShieldBrowser.init()` to create/get instance.
 */
export class ShieldBrowser {
  private static instance: ShieldBrowser | null = null;

  private client: WasmClient;
  private config: Required<ShieldClientConfig>;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;

  private constructor(config: ShieldClientConfig) {
    this.client = new WasmClient();
    this.config = {
      keyEndpoint: config.keyEndpoint,
      keyRefreshMargin: config.keyRefreshMargin ?? 60,
      autoRefresh: config.autoRefresh ?? true,
      interceptFetch: config.interceptFetch ?? true,
      encryptedIndicator: config.encryptedIndicator ?? 'encrypted',
      onKeyRefresh: config.onKeyRefresh ?? (() => {}),
      onDecryptError: config.onDecryptError ?? ((err) => console.error('Shield decrypt error:', err)),
      keyEndpointHeaders: config.keyEndpointHeaders ?? {},
    };
  }

  /**
   * Initialize the Shield Browser SDK.
   *
   * @param keyEndpoint - URL to fetch session key from
   * @param config - Additional configuration options
   * @returns Initialized ShieldBrowser instance
   *
   * @example
   * ```javascript
   * await ShieldBrowser.init('/api/shield-key');
   * ```
   */
  static async init(
    keyEndpoint: string,
    config?: Partial<Omit<ShieldClientConfig, 'keyEndpoint'>>
  ): Promise<ShieldBrowser> {
    // Initialize WASM if not already done
    if (!wasmInitialized) {
      await init();
      wasmInitialized = true;
    }

    // Create or reuse instance
    if (ShieldBrowser.instance) {
      console.warn('ShieldBrowser already initialized, returning existing instance');
      return ShieldBrowser.instance;
    }

    const instance = new ShieldBrowser({ keyEndpoint, ...config });

    // Fetch initial key
    await instance.refreshKey();

    // Install fetch hook if enabled
    if (instance.config.interceptFetch) {
      installFetchHook(
        instance.client,
        instance.config.encryptedIndicator,
        instance.config.onDecryptError
      );
    }

    ShieldBrowser.instance = instance;
    return instance;
  }

  /**
   * Get the current instance (throws if not initialized).
   */
  static getInstance(): ShieldBrowser {
    if (!ShieldBrowser.instance) {
      throw new Error('ShieldBrowser not initialized. Call ShieldBrowser.init() first.');
    }
    return ShieldBrowser.instance;
  }

  /**
   * Check if SDK is initialized.
   */
  static isInitialized(): boolean {
    return ShieldBrowser.instance !== null;
  }

  /**
   * Refresh the session key from the server.
   */
  async refreshKey(): Promise<SessionInfo> {
    const response = await fetch(this.config.keyEndpoint, {
      headers: this.config.keyEndpointHeaders,
      credentials: 'same-origin',
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch key: ${response.status} ${response.statusText}`);
    }

    const keyData: KeyResponse = await response.json();

    // Set key in WASM client
    this.client.setKey(
      keyData.key,
      keyData.session_id,
      BigInt(keyData.expires_at),
      keyData.service
    );

    const sessionInfo: SessionInfo = {
      sessionId: keyData.session_id,
      expiresAt: keyData.expires_at,
      algorithm: keyData.algorithm,
      service: keyData.service,
    };

    // Schedule auto-refresh if enabled
    if (this.config.autoRefresh) {
      this.scheduleRefresh(keyData.expires_at);
    }

    // Notify callback
    this.config.onKeyRefresh(sessionInfo);

    return sessionInfo;
  }

  /**
   * Schedule automatic key refresh before expiration.
   */
  private scheduleRefresh(expiresAt: number): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }

    const now = Date.now() / 1000;
    const refreshAt = expiresAt - this.config.keyRefreshMargin;
    const delayMs = Math.max(0, (refreshAt - now) * 1000);

    this.refreshTimer = setTimeout(async () => {
      try {
        await this.refreshKey();
      } catch (error) {
        console.error('Shield auto-refresh failed:', error);
      }
    }, delayMs);
  }

  /**
   * Manually decrypt data (for non-fetch use cases).
   *
   * @param encryptedBase64 - Base64-encoded ciphertext
   * @returns Decrypted bytes
   */
  decrypt(encryptedBase64: string): Uint8Array {
    return this.client.decrypt(encryptedBase64);
  }

  /**
   * Decrypt a JSON envelope.
   *
   * @param envelopeJson - JSON string with encrypted envelope
   * @returns Decrypted JSON string
   */
  decryptEnvelope(envelopeJson: string): string {
    return this.client.decryptEnvelope(envelopeJson);
  }

  /**
   * Check if the current key is valid.
   */
  isKeyValid(): boolean {
    return this.client.isValid();
  }

  /**
   * Get current session information.
   */
  getSession(): SessionInfo | null {
    const sessionId = this.client.getSessionId();
    const expiresAt = this.client.getExpiresAt();

    if (!sessionId || expiresAt === undefined) {
      return null;
    }

    return {
      sessionId,
      expiresAt: Number(expiresAt),
      algorithm: 'shield-v1',
      service: '',
    };
  }

  /**
   * Destroy the client and restore original fetch.
   */
  destroy(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }

    if (isFetchHookInstalled()) {
      uninstallFetchHook();
    }

    this.client.clear();
    ShieldBrowser.instance = null;
  }
}

// Export WASM client for advanced usage
export { WasmClient as ShieldClient };

// Re-export fetch hook utilities
export { installFetchHook, uninstallFetchHook, isFetchHookInstalled };

// Default export
export default ShieldBrowser;
