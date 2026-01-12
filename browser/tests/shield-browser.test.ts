/**
 * Tests for Shield Browser SDK main class
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock the WASM module before importing ShieldBrowser
vi.mock('../pkg/shield_browser.js', () => ({
  default: vi.fn().mockResolvedValue(undefined),
  ShieldClient: vi.fn().mockImplementation(() => ({
    setKey: vi.fn(),
    decrypt: vi.fn().mockReturnValue(new Uint8Array([1, 2, 3])),
    decryptEnvelope: vi.fn().mockReturnValue('{"decrypted":true}'),
    isValid: vi.fn().mockReturnValue(true),
    getSessionId: vi.fn().mockReturnValue('session-123'),
    getExpiresAt: vi.fn().mockReturnValue(BigInt(Date.now() / 1000 + 3600)),
    clear: vi.fn(),
  })),
}));

// Mock fetch-hook module
vi.mock('../js/fetch-hook.js', () => ({
  installFetchHook: vi.fn(),
  uninstallFetchHook: vi.fn(),
  isFetchHookInstalled: vi.fn().mockReturnValue(false),
}));

// Import after mocks are set up
import { ShieldBrowser } from '../js/index';
import { installFetchHook, uninstallFetchHook, isFetchHookInstalled } from '../js/fetch-hook';

describe('ShieldBrowser', () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    vi.clearAllMocks();

    // Reset singleton
    if (ShieldBrowser.isInitialized()) {
      ShieldBrowser.getInstance().destroy();
    }
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    if (ShieldBrowser.isInitialized()) {
      ShieldBrowser.getInstance().destroy();
    }
  });

  describe('init', () => {
    it('should initialize the SDK', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );

      const instance = await ShieldBrowser.init('/api/key');

      expect(instance).toBeDefined();
      expect(ShieldBrowser.isInitialized()).toBe(true);
    });

    it('should fetch key from endpoint', async () => {
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );
      globalThis.fetch = mockFetch;

      await ShieldBrowser.init('/api/key');

      expect(mockFetch).toHaveBeenCalledWith('/api/key', expect.objectContaining({
        credentials: 'same-origin',
      }));
    });

    it('should install fetch hook by default', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );

      await ShieldBrowser.init('/api/key');

      expect(installFetchHook).toHaveBeenCalled();
    });

    it('should not install fetch hook when disabled', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );

      await ShieldBrowser.init('/api/key', { interceptFetch: false });

      expect(installFetchHook).not.toHaveBeenCalled();
    });

    it('should return existing instance if already initialized', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      const instance1 = await ShieldBrowser.init('/api/key');
      const instance2 = await ShieldBrowser.init('/api/key2');

      expect(instance1).toBe(instance2);
      expect(consoleSpy).toHaveBeenCalledWith(
        'ShieldBrowser already initialized, returning existing instance'
      );
      consoleSpy.mockRestore();
    });

    it('should throw on key fetch failure', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response('Unauthorized', { status: 401, statusText: 'Unauthorized' })
      );

      await expect(ShieldBrowser.init('/api/key')).rejects.toThrow(
        'Failed to fetch key: 401 Unauthorized'
      );
    });

    it('should pass custom headers to key endpoint', async () => {
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );
      globalThis.fetch = mockFetch;

      await ShieldBrowser.init('/api/key', {
        keyEndpointHeaders: { 'X-Custom': 'value' },
      });

      expect(mockFetch).toHaveBeenCalledWith('/api/key', expect.objectContaining({
        headers: { 'X-Custom': 'value' },
      }));
    });

    it('should call onKeyRefresh callback', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );
      const onKeyRefresh = vi.fn();

      await ShieldBrowser.init('/api/key', { onKeyRefresh });

      expect(onKeyRefresh).toHaveBeenCalledWith(expect.objectContaining({
        sessionId: 'sess-123',
        algorithm: 'shield-v1',
        service: 'test.com',
      }));
    });
  });

  describe('getInstance', () => {
    it('should return instance after init', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );

      await ShieldBrowser.init('/api/key');
      const instance = ShieldBrowser.getInstance();

      expect(instance).toBeDefined();
    });

    it('should throw if not initialized', () => {
      expect(() => ShieldBrowser.getInstance()).toThrow(
        'ShieldBrowser not initialized. Call ShieldBrowser.init() first.'
      );
    });
  });

  describe('isInitialized', () => {
    it('should return false before init', () => {
      expect(ShieldBrowser.isInitialized()).toBe(false);
    });

    it('should return true after init', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );

      await ShieldBrowser.init('/api/key');

      expect(ShieldBrowser.isInitialized()).toBe(true);
    });
  });

  describe('decrypt', () => {
    it('should decrypt base64 data', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );

      const instance = await ShieldBrowser.init('/api/key');
      const result = instance.decrypt('encrypted_base64');

      expect(result).toBeInstanceOf(Uint8Array);
    });
  });

  describe('decryptEnvelope', () => {
    it('should decrypt JSON envelope', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );

      const instance = await ShieldBrowser.init('/api/key');
      const result = instance.decryptEnvelope('{"encrypted":true,"data":"xyz"}');

      expect(result).toBe('{"decrypted":true}');
    });
  });

  describe('isKeyValid', () => {
    it('should return key validity status', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );

      const instance = await ShieldBrowser.init('/api/key');

      expect(instance.isKeyValid()).toBe(true);
    });
  });

  describe('getSession', () => {
    it('should return session info', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );

      const instance = await ShieldBrowser.init('/api/key');
      const session = instance.getSession();

      expect(session).toEqual(expect.objectContaining({
        sessionId: 'session-123',
        algorithm: 'shield-v1',
      }));
    });
  });

  describe('destroy', () => {
    it('should clean up resources', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );
      vi.mocked(isFetchHookInstalled).mockReturnValue(true);

      const instance = await ShieldBrowser.init('/api/key');
      instance.destroy();

      expect(ShieldBrowser.isInitialized()).toBe(false);
      expect(uninstallFetchHook).toHaveBeenCalled();
    });
  });

  describe('refreshKey', () => {
    it('should refresh the key', async () => {
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({
          key: 'base64key==',
          session_id: 'sess-123',
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          algorithm: 'shield-v1',
          service: 'test.com',
        }), { status: 200 })
      );
      globalThis.fetch = mockFetch;

      const instance = await ShieldBrowser.init('/api/key');
      mockFetch.mockClear();

      await instance.refreshKey();

      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });
});
