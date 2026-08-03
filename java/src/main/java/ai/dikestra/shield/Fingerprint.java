package ai.dikestra.shield;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Hardware fingerprinting for device-bound encryption.
 *
 * <p>Collects platform-specific hardware identifiers to create device-bound keys.
 * Adapted from SaaSClient-SideLicensingSystem.
 *
 * <p>Example:
 * <pre>{@code
 * String fp = Fingerprint.collect(FingerprintMode.COMBINED);
 * Shield shield = Shield.withFingerprint("password", "github.com", FingerprintMode.COMBINED);
 * }</pre>
 */
public class Fingerprint {

    /**
     * Fingerprint collection mode.
     */
    public enum FingerprintMode {
        /** No fingerprinting (backward compatible) */
        NONE,
        /** Motherboard serial only */
        MOTHERBOARD,
        /** CPU identifier only */
        CPU,
        /** Motherboard + CPU (recommended) */
        COMBINED
    }

    /**
     * Collect hardware fingerprint.
     *
     * @param mode Fingerprint mode
     * @return Fingerprint string (SHA-256 hex), or empty for NONE
     * @throws Exception If hardware identifiers cannot be collected
     */
    public static String collect(FingerprintMode mode) throws Exception {
        if (mode == FingerprintMode.NONE) {
            return "";
        }

        if (mode == FingerprintMode.MOTHERBOARD) {
            return getMotherboardSerial();
        }

        if (mode == FingerprintMode.CPU) {
            return getCpuId();
        }

        if (mode == FingerprintMode.COMBINED) {
            List<String> components = new ArrayList<>();

            try {
                components.add(getMotherboardSerial());
            } catch (Exception e) {
                // Continue without motherboard
            }

            try {
                components.add(getCpuId());
            } catch (Exception e) {
                // Continue without CPU
            }

            if (components.isEmpty()) {
                throw new Exception("Hardware fingerprint unavailable");
            }

            // Create SHA-256 hash of combined components
            String combined = String.join("-", components);
            return sha256Hex(combined);
        }

        throw new IllegalArgumentException("Unknown fingerprint mode: " + mode);
    }

    /**
     * Get motherboard serial number (platform-specific).
     */
    private static String getMotherboardSerial() throws Exception {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            Process process = Runtime.getRuntime().exec(
                new String[]{"wmic", "baseboard", "get", "serialnumber", "/value"}
            );

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("SerialNumber=")) {
                        String serial = line.replace("SerialNumber=", "").trim();
                        if (!serial.isEmpty() && !serial.equals("To be filled by O.E.M.")) {
                            return serial;
                        }
                    }
                }
            }
        } else if (os.contains("linux")) {
            // Try DMI sysfs first
            try {
                String serial = new String(Files.readAllBytes(
                    Paths.get("/sys/class/dmi/id/board_serial")
                )).trim();
                if (!serial.isEmpty() && !serial.equals("To be filled by O.E.M.")) {
                    return serial;
                }
            } catch (Exception e) {
                // Fall through to dmidecode
            }

            // Fallback to dmidecode
            Process process = Runtime.getRuntime().exec(
                new String[]{"dmidecode", "-s", "baseboard-serial-number"}
            );

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String serial = reader.readLine();
                if (serial != null) {
                    serial = serial.trim();
                    if (!serial.isEmpty() && !serial.equals("To be filled by O.E.M.")) {
                        return serial;
                    }
                }
            }
        } else if (os.contains("mac")) {
            Process process = Runtime.getRuntime().exec(
                new String[]{"system_profiler", "SPHardwareDataType"}
            );

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("Serial Number")) {
                        String[] parts = line.split(":");
                        if (parts.length >= 2) {
                            return parts[1].trim();
                        }
                    }
                }
            }
        }

        throw new Exception("Motherboard serial number unavailable");
    }

    /**
     * Get CPU identifier (platform-specific).
     */
    private static String getCpuId() throws Exception {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            Process process = Runtime.getRuntime().exec(
                new String[]{"wmic", "cpu", "get", "ProcessorId", "/value"}
            );

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("ProcessorId=")) {
                        String cpuId = line.replace("ProcessorId=", "").trim();
                        if (!cpuId.isEmpty()) {
                            return cpuId;
                        }
                    }
                }
            }
        } else if (os.contains("linux")) {
            String content = new String(Files.readAllBytes(Paths.get("/proc/cpuinfo")));
            for (String line : content.split("\n")) {
                if (line.startsWith("processor") && line.contains("0")) {
                    // Use first processor as identifier (hashed)
                    return sha256Hex(line);
                }
            }
        } else if (os.contains("mac")) {
            Process process = Runtime.getRuntime().exec(
                new String[]{"sysctl", "-n", "machdep.cpu.brand_string"}
            );

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String cpuInfo = reader.readLine();
                if (cpuInfo != null) {
                    cpuInfo = cpuInfo.trim();
                    if (!cpuInfo.isEmpty()) {
                        return sha256Hex(cpuInfo);
                    }
                }
            }
        }

        throw new Exception("CPU identifier unavailable");
    }

    /**
     * SHA-256 hash helper.
     */
    private static String sha256Hex(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input.getBytes());

        StringBuilder hex = new StringBuilder();
        for (byte b : digest) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}
