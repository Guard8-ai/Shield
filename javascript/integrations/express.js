/**
 * Shield Express.js Middleware
 *
 * Automatic encryption for Express.js applications.
 *
 * Usage:
 *   const express = require('express');
 *   const { shieldMiddleware, shieldProtected } = require('@guard8/shield/integrations/express');
 *
 *   const app = express();
 *
 *   // Global middleware
 *   app.use(shieldMiddleware({
 *     password: 'your-password',
 *     service: 'your-app.com'
 *   }));
 *
 *   // Or per-route
 *   app.get('/api/secret', shieldProtected({ password, service }), (req, res) => {
 *     res.json({ secret: 'data' });
 *   });
 */

const { Shield } = require('../src/shield');

/**
 * Express middleware for automatic response encryption
 *
 * @param {Object} options
 * @param {string} options.password - Shield password
 * @param {string} options.service - Shield service identifier
 * @param {string[]} [options.paths] - Paths to encrypt (default: all)
 * @param {string[]} [options.excludePaths] - Paths to exclude
 */
function shieldMiddleware(options) {
    const { password, service, paths, excludePaths } = options;

    if (!password || !service) {
        throw new Error('Shield middleware requires password and service');
    }

    const shield = new Shield(password, service);

    return (req, res, next) => {
        // Check if path should be encrypted
        if (paths && !paths.some(p => req.path.startsWith(p))) {
            return next();
        }

        if (excludePaths && excludePaths.some(p => req.path.startsWith(p))) {
            return next();
        }

        // Store original json method
        const originalJson = res.json.bind(res);

        // Override json method to encrypt
        res.json = (data) => {
            try {
                const plaintext = Buffer.from(JSON.stringify(data));
                const encrypted = shield.encrypt(plaintext);
                const encryptedB64 = encrypted.toString('base64');

                return originalJson({
                    encrypted: true,
                    data: encryptedB64
                });
            } catch (err) {
                // On error, send original data
                console.error('Shield encryption error:', err);
                return originalJson(data);
            }
        };

        next();
    };
}

/**
 * Route-level middleware for encrypted responses
 *
 * @param {Object} options
 * @param {string} options.password - Shield password
 * @param {string} options.service - Shield service identifier
 */
function shieldProtected(options) {
    const { password, service } = options;

    if (!password || !service) {
        throw new Error('shieldProtected requires password and service');
    }

    const shield = new Shield(password, service);

    return (req, res, next) => {
        const originalJson = res.json.bind(res);

        res.json = (data) => {
            const plaintext = Buffer.from(JSON.stringify(data));
            const encrypted = shield.encrypt(plaintext);
            const encryptedB64 = encrypted.toString('base64');

            return originalJson({
                encrypted: true,
                data: encryptedB64
            });
        };

        next();
    };
}

/**
 * Middleware requiring encrypted request body
 *
 * @param {Object} options
 * @param {string} options.password - Shield password
 * @param {string} options.service - Shield service identifier
 */
function shieldRequired(options) {
    const { password, service } = options;

    if (!password || !service) {
        throw new Error('shieldRequired requires password and service');
    }

    const shield = new Shield(password, service);

    return (req, res, next) => {
        if (!req.body || !req.body.encrypted || !req.body.data) {
            return res.status(400).json({
                error: 'Encrypted request body required'
            });
        }

        try {
            const encrypted = Buffer.from(req.body.data, 'base64');
            const decrypted = shield.decrypt(encrypted);
            req.shieldData = JSON.parse(decrypted.toString());
            next();
        } catch (err) {
            return res.status(400).json({
                error: `Decryption failed: ${err.message}`
            });
        }
    };
}

/**
 * Create Shield instance for manual encryption
 *
 * @param {string} password
 * @param {string} service
 * @returns {Shield}
 */
function createShield(password, service) {
    return new Shield(password, service);
}

/**
 * Express error handler for Shield errors
 */
function shieldErrorHandler(err, req, res, next) {
    if (err.name === 'ShieldError') {
        return res.status(400).json({
            error: 'Encryption/decryption error',
            message: err.message
        });
    }
    next(err);
}

module.exports = {
    shieldMiddleware,
    shieldProtected,
    shieldRequired,
    createShield,
    shieldErrorHandler
};
