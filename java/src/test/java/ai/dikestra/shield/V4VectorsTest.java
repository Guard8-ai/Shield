package ai.dikestra.shield;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Conformance: reproduce the Rust-generated v4 vectors byte-for-byte.
 *
 * Dependency-free: parses the small, well-formed tests/v4_test_vectors.json by
 * scanning each object inside the deterministic arrays and extracting fields with
 * regular expressions. Proves the Java binding derives identical master + AEAD
 * keys, reproduces every ciphertext byte-for-byte, and decrypts each vector.
 */
public class V4VectorsTest {

    private static Path vectorsPath() {
        Path dir = Paths.get("").toAbsolutePath();
        for (int i = 0; i < 8 && dir != null; i++) {
            Path candidate = dir.resolve("tests").resolve("v4_test_vectors.json");
            if (Files.exists(candidate)) return candidate;
            dir = dir.getParent();
        }
        throw new RuntimeException("v4_test_vectors.json not found");
    }

    private static String str(String obj, String field) {
        Matcher m = Pattern.compile("\"" + field + "\"\\s*:\\s*\"([^\"]*)\"").matcher(obj);
        return m.find() ? m.group(1) : null;
    }

    private static long num(String obj, String field) {
        Matcher m = Pattern.compile("\"" + field + "\"\\s*:\\s*(\\d+)").matcher(obj);
        return m.find() ? Long.parseLong(m.group(1)) : 0L;
    }

    /** Extract each brace-balanced object inside the named JSON array. */
    private static List<String> objectsInArray(String json, String arrayName) {
        List<String> objects = new ArrayList<>();
        int key = json.indexOf("\"" + arrayName + "\"");
        if (key < 0) return objects;
        int start = json.indexOf('[', key);
        int depth = 0, objStart = -1;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '[') { depth++; }
            else if (c == ']') { depth--; if (depth == 0) break; }
            else if (c == '{') { if (objStart < 0) objStart = i; }
            else if (c == '}') {
                if (objStart >= 0) { objects.add(json.substring(objStart, i + 1)); objStart = -1; }
            }
        }
        return objects;
    }

    private static List<String> allVectors() throws IOException {
        String json = new String(Files.readAllBytes(vectorsPath()));
        List<String> all = new ArrayList<>(objectsInArray(json, "deterministic_vectors"));
        all.addAll(objectsInArray(json, "deterministic_vectors_chacha"));
        return all;
    }

    private static byte[] hex(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        }
        return out;
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte suiteByte(String obj) {
        return "0x02".equals(str(obj, "suite")) ? Shield.SUITE_CHACHA20_POLY1305 : Shield.SUITE_AES_GCM;
    }

    private static byte[] masterFor(String obj) {
        if ("password".equals(str(obj, "mode"))) {
            Shield s = new Shield(str(obj, "password"), str(obj, "service"),
                    hex(str(obj, "salt_hex")), (int) num(obj, "iterations"), null);
            return s.getKey();
        }
        return hex(str(obj, "key_hex"));
    }

    @Test
    void testKdfVectors() throws IOException {
        List<String> vectors = allVectors();
        assertTrue(vectors.size() >= 6, "expected vectors loaded");
        for (String v : vectors) {
            byte[] master = masterFor(v);
            assertEquals(str(v, "master_key_hex"), toHex(master), "master drift " + str(v, "name"));
            assertEquals(str(v, "aead_key_hex"), toHex(Shield.deriveAeadKey(master)),
                    "aead drift " + str(v, "name"));
        }
    }

    @Test
    void testReproduceBytes() throws IOException {
        for (String v : allVectors()) {
            byte[] aeadKey = Shield.deriveAeadKey(masterFor(v));
            byte[] salt = "password".equals(str(v, "mode")) ? hex(str(v, "salt_hex")) : null;
            byte[] out = Shield.sealDeterministic(aeadKey, suiteByte(v), salt,
                    hex(str(v, "nonce_hex")), num(v, "timestamp_ms"), (int) num(v, "pad_len"),
                    hex(str(v, "padding_hex")), hex(str(v, "plaintext_hex")));
            assertEquals(str(v, "expected_output_hex"), toHex(out), "BYTE DRIFT " + str(v, "name"));
        }
    }

    @Test
    void testDecryptVectors() throws IOException {
        for (String v : allVectors()) {
            byte[] aeadKey = Shield.deriveAeadKey(masterFor(v));
            byte[] encrypted = hex(str(v, "expected_output_hex"));
            int aadLen = "password".equals(str(v, "mode")) ? 2 + Shield.SALT_SIZE : 2;
            byte[] opened = Shield.openCiphertext(aeadKey, suiteByte(v), encrypted, aadLen, null);
            assertEquals(str(v, "plaintext_hex"), toHex(opened), "decrypt failed " + str(v, "name"));
        }
    }
}
