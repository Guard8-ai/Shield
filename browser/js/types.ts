/**
 * Shield Browser SDK - TypeScript Definitions
 */

/** Configuration for ShieldClient initialization */
export interface ShieldClientConfig {
  /** URL to fetch session key from (e.g., '/api/shield-key') */
  keyEndpoint: string;

  /** Seconds before expiry to auto-refresh key (default: 60) */
  keyRefreshMargin?: number;

  /** Whether to auto-refresh expired keys (default: true) */
  autoRefresh?: boolean;

  /** Whether to monkey-patch fetch() for auto-decryption (default: true) */
  interceptFetch?: boolean;

  /** JSON field name indicating encrypted payload (default: 'encrypted') */
  encryptedIndicator?: string;

  /** Callback when key is refreshed */
  onKeyRefresh?: (session: SessionInfo) => void;

  /** Callback when decryption fails */
  onDecryptError?: (error: Error, response: Response) => void;

  /** Additional headers for key endpoint request */
  keyEndpointHeaders?: Record<string, string>;
}

/** Session key information from server */
export interface SessionInfo {
  /** Session identifier */
  sessionId: string;

  /** Expiration timestamp (Unix seconds) */
  expiresAt: number;

  /** Algorithm version */
  algorithm: string;

  /** Service name */
  service: string;
}

/** Encrypted response envelope from server */
export interface EncryptedEnvelope {
  /** Always true for encrypted responses */
  encrypted: true;

  /** Base64-encoded ciphertext */
  data: string;

  /** Optional service identifier */
  service?: string;
}

/** Server response for key endpoint */
export interface KeyResponse {
  /** Base64-encoded 32-byte key */
  key: string;

  /** Session identifier */
  session_id: string;

  /** Expiration timestamp (Unix seconds) */
  expires_at: number;

  /** Algorithm version (e.g., 'shield-v1') */
  algorithm: string;

  /** Service name */
  service: string;
}
