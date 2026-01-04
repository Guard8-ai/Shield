package ai.guard8.shield;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

/**
 * TOTP - Time-based One-Time Password (RFC 6238)
 */
public class TOTP {
    public static final int DEFAULT_DIGITS = 6;
    public static final int DEFAULT_INTERVAL = 30;
    public static final int DEFAULT_SECRET_SIZE = 20;

    private final byte[] secret;
    private final int digits;
    private final long interval;

    public TOTP(byte[] secret) {
        this(secret, DEFAULT_DIGITS, DEFAULT_INTERVAL);
    }

    public TOTP(byte[] secret, int digits, int interval) {
        this.secret = Arrays.copyOf(secret, secret.length);
        this.digits = digits > 0 ? digits : DEFAULT_DIGITS;
        this.interval = interval > 0 ? interval : DEFAULT_INTERVAL;
    }

    public static byte[] generateSecret() {
        return Shield.randomBytes(DEFAULT_SECRET_SIZE);
    }

    public String generate() {
        return generate(System.currentTimeMillis() / 1000);
    }

    public String generate(long timestamp) {
        if (timestamp == 0) {
            timestamp = System.currentTimeMillis() / 1000;
        }
        long counter = timestamp / interval;
        return generateHOTP(counter);
    }

    public boolean verify(String code) {
        return verify(code, 0, 1);
    }

    public boolean verify(String code, long timestamp, int window) {
        if (timestamp == 0) {
            timestamp = System.currentTimeMillis() / 1000;
        }
        if (window <= 0) {
            window = 1;
        }

        for (int i = 0; i <= window; i++) {
            // Check current and past
            if (generate(timestamp - i * interval).equals(code)) {
                return true;
            }
            // Check future (except for i=0)
            if (i > 0 && generate(timestamp + i * interval).equals(code)) {
                return true;
            }
        }
        return false;
    }

    private String generateHOTP(long counter) {
        byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();

        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            byte[] hash = mac.doFinal(counterBytes);

            int offset = hash[19] & 0x0f;
            int code = ((hash[offset] & 0x7f) << 24) |
                       ((hash[offset + 1] & 0xff) << 16) |
                       ((hash[offset + 2] & 0xff) << 8) |
                       (hash[offset + 3] & 0xff);

            int modulo = 1;
            for (int i = 0; i < digits; i++) {
                modulo *= 10;
            }

            return String.format("%0" + digits + "d", code % modulo);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA1 not available", e);
        }
    }

    public String toBase32() {
        return Base32.encode(secret);
    }

    public static TOTP fromBase32(String encoded) {
        return new TOTP(Base32.decode(encoded));
    }

    public String getProvisioningUri(String account, String issuer) {
        String secretB32 = toBase32();
        return String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
            issuer, account, secretB32, issuer, digits, interval
        );
    }

    public byte[] getSecret() {
        return Arrays.copyOf(secret, secret.length);
    }

    public void wipe() {
        Arrays.fill(secret, (byte) 0);
    }

    // Simple Base32 encoder/decoder
    private static class Base32 {
        private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        public static String encode(byte[] data) {
            StringBuilder result = new StringBuilder();
            int buffer = 0;
            int bufferLength = 0;

            for (byte b : data) {
                buffer = (buffer << 8) | (b & 0xff);
                bufferLength += 8;
                while (bufferLength >= 5) {
                    bufferLength -= 5;
                    result.append(ALPHABET.charAt((buffer >> bufferLength) & 0x1f));
                }
            }
            if (bufferLength > 0) {
                result.append(ALPHABET.charAt((buffer << (5 - bufferLength)) & 0x1f));
            }
            return result.toString();
        }

        public static byte[] decode(String encoded) {
            encoded = encoded.toUpperCase().replaceAll("=", "");
            byte[] result = new byte[encoded.length() * 5 / 8];
            int buffer = 0;
            int bufferLength = 0;
            int index = 0;

            for (char c : encoded.toCharArray()) {
                int val = ALPHABET.indexOf(c);
                if (val < 0) continue;
                buffer = (buffer << 5) | val;
                bufferLength += 5;
                if (bufferLength >= 8) {
                    bufferLength -= 8;
                    result[index++] = (byte) ((buffer >> bufferLength) & 0xff);
                }
            }
            return Arrays.copyOf(result, index);
        }
    }
}
