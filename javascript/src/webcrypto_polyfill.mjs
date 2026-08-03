// Ensure the WebCrypto API is available as globalThis.crypto.
//
// The @noble/post-quantum and @noble/curves packages call
// crypto.getRandomValues(). Node 20+ exposes globalThis.crypto by default, but
// older runtimes (Node 16/18) and some sandboxed test runners do not, throwing
// "crypto.getRandomValues must be defined". Importing this module first wires
// Node's WebCrypto implementation into the global scope. It is a no-op where
// globalThis.crypto already exists.
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) {
    globalThis.crypto = webcrypto;
}
