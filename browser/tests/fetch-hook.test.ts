/**
 * Tests for Shield Browser SDK fetch interceptor
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  installFetchHook,
  uninstallFetchHook,
  isFetchHookInstalled,
} from '../js/fetch-hook';

// Mock ShieldClient
const createMockClient = (options: {
  isValid?: boolean;
  decryptResult?: string;
  throwOnDecrypt?: boolean;
} = {}) => ({
  isValid: vi.fn().mockReturnValue(options.isValid ?? true),
  decryptEnvelope: vi.fn().mockImplementation((text: string) => {
    if (options.throwOnDecrypt) {
      throw new Error('Decryption failed');
    }
    return options.decryptResult ?? '{"message":"decrypted"}';
  }),
});

// Mock Response helper
const createMockResponse = (body: string, contentType = 'application/json') => {
  return new Response(body, {
    status: 200,
    statusText: 'OK',
    headers: { 'content-type': contentType },
  });
};

describe('Fetch Hook', () => {
  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    // Reset fetch hook state
    uninstallFetchHook();
  });

  afterEach(() => {
    uninstallFetchHook();
    globalThis.fetch = originalFetch;
  });

  describe('installFetchHook', () => {
    it('should install the fetch hook', () => {
      const client = createMockClient();
      expect(isFetchHookInstalled()).toBe(false);

      installFetchHook(client as any);

      expect(isFetchHookInstalled()).toBe(true);
    });

    it('should not install twice', () => {
      const client = createMockClient();
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      installFetchHook(client as any);
      installFetchHook(client as any);

      expect(consoleSpy).toHaveBeenCalledWith('Shield fetch hook already installed');
      consoleSpy.mockRestore();
    });
  });

  describe('uninstallFetchHook', () => {
    it('should uninstall the fetch hook', () => {
      const client = createMockClient();
      installFetchHook(client as any);
      expect(isFetchHookInstalled()).toBe(true);

      uninstallFetchHook();

      expect(isFetchHookInstalled()).toBe(false);
    });

    it('should do nothing if not installed', () => {
      expect(isFetchHookInstalled()).toBe(false);
      uninstallFetchHook();
      expect(isFetchHookInstalled()).toBe(false);
    });
  });

  describe('fetch interception', () => {
    it('should pass through non-JSON responses unchanged', async () => {
      const client = createMockClient();
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response('plain text', {
          headers: { 'content-type': 'text/plain' },
        })
      );

      installFetchHook(client as any);
      const response = await fetch('/api/test');
      const text = await response.text();

      expect(text).toBe('plain text');
      expect(client.decryptEnvelope).not.toHaveBeenCalled();
    });

    it('should pass through non-encrypted JSON responses unchanged', async () => {
      const client = createMockClient();
      const originalData = { message: 'hello', notEncrypted: true };
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(JSON.stringify(originalData))
      );

      installFetchHook(client as any);
      const response = await fetch('/api/test');
      const data = await response.json();

      expect(data).toEqual(originalData);
      expect(client.decryptEnvelope).not.toHaveBeenCalled();
    });

    it('should decrypt encrypted envelope responses', async () => {
      const client = createMockClient({ decryptResult: '{"secret":"value"}' });
      const encryptedEnvelope = { encrypted: true, data: 'base64ciphertext' };
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(JSON.stringify(encryptedEnvelope))
      );

      installFetchHook(client as any);
      const response = await fetch('/api/test');
      const data = await response.json();

      expect(data).toEqual({ secret: 'value' });
      expect(client.decryptEnvelope).toHaveBeenCalled();
    });

    it('should use custom encrypted indicator', async () => {
      const client = createMockClient({ decryptResult: '{"decrypted":true}' });
      const customEnvelope = { isShielded: true, data: 'ciphertext' };
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(JSON.stringify(customEnvelope))
      );

      installFetchHook(client as any, 'isShielded');
      const response = await fetch('/api/test');
      const data = await response.json();

      expect(data).toEqual({ decrypted: true });
    });

    it('should pass through if client key is invalid', async () => {
      const client = createMockClient({ isValid: false });
      const encryptedEnvelope = { encrypted: true, data: 'ciphertext' };
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(JSON.stringify(encryptedEnvelope))
      );
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      installFetchHook(client as any);
      const response = await fetch('/api/test');
      const data = await response.json();

      expect(data).toEqual(encryptedEnvelope);
      expect(consoleSpy).toHaveBeenCalledWith(
        'Shield: Key expired or not set, returning encrypted response'
      );
      consoleSpy.mockRestore();
    });

    it('should call error handler on decryption failure', async () => {
      const client = createMockClient({ throwOnDecrypt: true });
      const encryptedEnvelope = { encrypted: true, data: 'invalid' };
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(JSON.stringify(encryptedEnvelope))
      );
      const onError = vi.fn();

      installFetchHook(client as any, 'encrypted', onError);
      const response = await fetch('/api/test');

      expect(onError).toHaveBeenCalled();
      expect(onError.mock.calls[0][0]).toBeInstanceOf(Error);
    });

    it('should return original response on decryption error', async () => {
      const client = createMockClient({ throwOnDecrypt: true });
      const encryptedEnvelope = { encrypted: true, data: 'invalid' };
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(JSON.stringify(encryptedEnvelope))
      );
      vi.spyOn(console, 'error').mockImplementation(() => {});

      installFetchHook(client as any);
      const response = await fetch('/api/test');
      const data = await response.json();

      // Should return original encrypted envelope on error
      expect(data).toEqual(encryptedEnvelope);
    });

    it('should handle invalid JSON gracefully', async () => {
      const client = createMockClient();
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse('not valid json {{{')
      );

      installFetchHook(client as any);
      const response = await fetch('/api/test');

      // Should not throw
      expect(response.status).toBe(200);
    });

    it('should preserve response status and headers', async () => {
      const client = createMockClient({ decryptResult: '{"ok":true}' });
      const encryptedEnvelope = { encrypted: true, data: 'ciphertext' };
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify(encryptedEnvelope), {
          status: 201,
          statusText: 'Created',
          headers: {
            'content-type': 'application/json',
            'x-custom': 'header',
          },
        })
      );

      installFetchHook(client as any);
      const response = await fetch('/api/test');

      expect(response.status).toBe(201);
      expect(response.statusText).toBe('Created');
      expect(response.headers.get('x-custom')).toBe('header');
    });
  });

  describe('encrypted envelope detection', () => {
    it('should detect standard encrypted envelope', async () => {
      const client = createMockClient({ decryptResult: '{}' });
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(JSON.stringify({ encrypted: true, data: 'abc' }))
      );

      installFetchHook(client as any);
      await fetch('/api/test');

      expect(client.decryptEnvelope).toHaveBeenCalled();
    });

    it('should not detect if encrypted is false', async () => {
      const client = createMockClient();
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(JSON.stringify({ encrypted: false, data: 'abc' }))
      );

      installFetchHook(client as any);
      await fetch('/api/test');

      expect(client.decryptEnvelope).not.toHaveBeenCalled();
    });

    it('should not detect if data field is missing', async () => {
      const client = createMockClient();
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(JSON.stringify({ encrypted: true }))
      );

      installFetchHook(client as any);
      await fetch('/api/test');

      expect(client.decryptEnvelope).not.toHaveBeenCalled();
    });

    it('should not detect if data field is not a string', async () => {
      const client = createMockClient();
      globalThis.fetch = vi.fn().mockResolvedValue(
        createMockResponse(JSON.stringify({ encrypted: true, data: 123 }))
      );

      installFetchHook(client as any);
      await fetch('/api/test');

      expect(client.decryptEnvelope).not.toHaveBeenCalled();
    });
  });
});
