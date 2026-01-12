package ai.guard8.shield;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * RecoveryCodes - Backup codes for 2FA.
 *
 * Use when user loses access to their authenticator app.
 * Each code can only be used once.
 */
public class RecoveryCodes {
    private static final SecureRandom random = new SecureRandom();
    private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();

    private final Set<String> codes;
    private final Set<String> used = new HashSet<>();

    /**
     * Create with existing codes.
     */
    public RecoveryCodes(List<String> codes) {
        this.codes = new HashSet<>(codes);
    }

    /**
     * Create with newly generated codes.
     */
    public RecoveryCodes() {
        this.codes = new HashSet<>(generateCodes(10, 8));
    }

    /**
     * Generate recovery codes.
     *
     * @param count Number of codes to generate
     * @param length Length of each code (must be even)
     * @return List of formatted codes (XXXX-XXXX)
     */
    public static List<String> generateCodes(int count, int length) {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            byte[] bytes = new byte[length / 2];
            random.nextBytes(bytes);

            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(HEX_CHARS[(b >> 4) & 0x0F]);
                sb.append(HEX_CHARS[b & 0x0F]);
            }

            String code = sb.toString();
            // Format as XXXX-XXXX
            String formatted = code.substring(0, 4) + "-" + code.substring(4);
            result.add(formatted);
        }
        return result;
    }

    /**
     * Verify and consume a recovery code.
     *
     * @param code Code to verify
     * @return true if valid (code is now consumed)
     */
    public boolean verify(String code) {
        // Normalize format (remove dashes, uppercase)
        String normalized = code.replace("-", "").toUpperCase();
        String formatted = normalized.substring(0, 4) + "-" + normalized.substring(4);

        if (used.contains(formatted)) {
            return false;
        }

        if (codes.contains(formatted)) {
            used.add(formatted);
            codes.remove(formatted);
            return true;
        }

        return false;
    }

    /**
     * Get remaining (unused) codes.
     */
    public List<String> getRemainingCodes() {
        return new ArrayList<>(codes);
    }

    /**
     * Get count of remaining codes.
     */
    public int getRemainingCount() {
        return codes.size();
    }

    /**
     * Get used codes.
     */
    public List<String> getUsedCodes() {
        return new ArrayList<>(used);
    }
}
