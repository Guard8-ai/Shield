/**
 * Hardware fingerprinting for device-bound encryption.
 *
 * Collects platform-specific hardware identifiers to create device-bound keys.
 * Adapted from SaaSClient-SideLicensingSystem.
 *
 * @module fingerprint
 */

const { execSync } = require('child_process');
const crypto = require('crypto');
const os = require('os');

/**
 * Fingerprint collection mode.
 * @enum {string}
 */
const FingerprintMode = {
    NONE: 'none',
    MOTHERBOARD: 'motherboard',
    CPU: 'cpu',
    COMBINED: 'combined'
};

/**
 * Collect hardware fingerprint.
 *
 * @param {string} mode - Fingerprint mode
 * @returns {string} Fingerprint string (MD5 hex), or empty for NONE
 * @throws {Error} If fingerprint unavailable
 *
 * @example
 * const fp = collectFingerprint(FingerprintMode.COMBINED);
 * console.log('Device fingerprint:', fp);
 */
function collectFingerprint(mode) {
    if (mode === FingerprintMode.NONE) {
        return '';
    }

    if (mode === FingerprintMode.MOTHERBOARD) {
        return getMotherboardSerial();
    }

    if (mode === FingerprintMode.CPU) {
        return getCpuId();
    }

    if (mode === FingerprintMode.COMBINED) {
        const components = [];

        try {
            components.push(getMotherboardSerial());
        } catch (e) {
            // Continue without motherboard
        }

        try {
            components.push(getCpuId());
        } catch (e) {
            // Continue without CPU
        }

        if (components.length === 0) {
            throw new Error('Hardware fingerprint unavailable');
        }

        // Create MD5 hash of combined components
        const combined = components.join('-');
        return crypto.createHash('md5').update(combined).digest('hex');
    }

    throw new Error(`Unknown fingerprint mode: ${mode}`);
}

/**
 * Get motherboard serial number (platform-specific).
 *
 * @returns {string} Motherboard serial
 * @throws {Error} If unavailable
 */
function getMotherboardSerial() {
    const platform = os.platform();

    if (platform === 'win32') {
        try {
            const output = execSync('wmic baseboard get serialnumber /value', {
                encoding: 'utf8',
                timeout: 5000
            });

            for (const line of output.split('\n')) {
                if (line.startsWith('SerialNumber=')) {
                    const serial = line.replace('SerialNumber=', '').trim();
                    if (serial && serial !== 'To be filled by O.E.M.') {
                        return serial;
                    }
                }
            }
        } catch (e) {
            // Fall through
        }
    } else if (platform === 'linux') {
        // Try DMI sysfs first
        try {
            const fs = require('fs');
            const serial = fs.readFileSync('/sys/class/dmi/id/board_serial', 'utf8').trim();
            if (serial && serial !== 'To be filled by O.E.M.') {
                return serial;
            }
        } catch (e) {
            // Fall through to dmidecode
        }

        // Fallback to dmidecode
        try {
            const output = execSync('dmidecode -s baseboard-serial-number', {
                encoding: 'utf8',
                timeout: 5000
            });
            const serial = output.trim();
            if (serial && serial !== 'To be filled by O.E.M.') {
                return serial;
            }
        } catch (e) {
            // Fall through
        }
    } else if (platform === 'darwin') {
        try {
            const output = execSync('system_profiler SPHardwareDataType', {
                encoding: 'utf8',
                timeout: 5000
            });

            for (const line of output.split('\n')) {
                if (line.includes('Serial Number')) {
                    const parts = line.split(':');
                    if (parts.length >= 2) {
                        return parts[1].trim();
                    }
                }
            }
        } catch (e) {
            // Fall through
        }
    }

    throw new Error('Motherboard serial number unavailable');
}

/**
 * Get CPU identifier (platform-specific).
 *
 * @returns {string} CPU ID
 * @throws {Error} If unavailable
 */
function getCpuId() {
    const platform = os.platform();

    if (platform === 'win32') {
        try {
            const output = execSync('wmic cpu get ProcessorId /value', {
                encoding: 'utf8',
                timeout: 5000
            });

            for (const line of output.split('\n')) {
                if (line.startsWith('ProcessorId=')) {
                    const cpuId = line.replace('ProcessorId=', '').trim();
                    if (cpuId) {
                        return cpuId;
                    }
                }
            }
        } catch (e) {
            // Fall through
        }
    } else if (platform === 'linux') {
        try {
            const fs = require('fs');
            const content = fs.readFileSync('/proc/cpuinfo', 'utf8');

            for (const line of content.split('\n')) {
                if (line.startsWith('processor') && line.includes('0')) {
                    // Use first processor as identifier (hashed)
                    return crypto.createHash('md5').update(line).digest('hex');
                }
            }
        } catch (e) {
            // Fall through
        }
    } else if (platform === 'darwin') {
        try {
            const output = execSync('sysctl -n machdep.cpu.brand_string', {
                encoding: 'utf8',
                timeout: 5000
            });
            const cpuInfo = output.trim();
            if (cpuInfo) {
                return crypto.createHash('md5').update(cpuInfo).digest('hex');
            }
        } catch (e) {
            // Fall through
        }
    }

    throw new Error('CPU identifier unavailable');
}

module.exports = {
    FingerprintMode,
    collectFingerprint
};
