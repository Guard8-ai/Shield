package ai.dikestra.shield;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Conformance: the Java post-quantum hybrid KEX must satisfy the shared
 * cross-language vectors (tests/pq_kex_vectors.json), proving byte-identical key
 * reconstruction and shared-key derivation against Python/Go/Rust/JS/C#.
 *
 * Dependency-free JSON: the vector fields are flat strings, extracted in document
 * order with a regex (one of each field per vector).
 */
public class PqKexVectorsTest {

    private static Path vectorsPath() {
        Path dir = Paths.get("").toAbsolutePath();
        for (int i = 0; i < 8 && dir != null; i++) {
            Path candidate = dir.resolve("tests").resolve("pq_kex_vectors.json");
            if (Files.exists(candidate)) return candidate;
            dir = dir.getParent();
        }
        throw new RuntimeException("pq_kex_vectors.json not found");
    }

    private static List<String> all(String json, String field) {
        List<String> out = new ArrayList<>();
        Matcher m = Pattern.compile("\"" + field + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        while (m.find()) out.add(m.group(1));
        return out;
    }

    private static byte[] hex(String h) {
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        return b;
    }

    private static String hx(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    @Test
    public void reproducesAllVectors() throws Exception {
        String json = new String(Files.readAllBytes(vectorsPath()));
        List<String> names = all(json, "name");
        List<String> privs = all(json, "bob_private_hex");
        List<String> bundles = all(json, "bob_public_bundle_hex");
        List<String> handshakes = all(json, "handshake_hex");
        List<String> shareds = all(json, "expected_shared_key_hex");
        assertFalse(privs.isEmpty(), "no vectors loaded");

        for (int i = 0; i < privs.size(); i++) {
            PqHybrid.HybridPrivateKey bob = PqHybrid.HybridPrivateKey.fromBytes(hex(privs.get(i)));
            assertEquals(bundles.get(i), hx(bob.publicKey().toBytes()), "bundle mismatch for " + names.get(i));
            byte[] shared = bob.accept(hex(handshakes.get(i)));
            assertEquals(shareds.get(i), hx(shared), "shared key mismatch for " + names.get(i));
        }
    }

    @Test
    public void initiateAcceptRoundTrips() {
        PqHybrid.HybridPrivateKey bob = PqHybrid.HybridPrivateKey.generate();
        PqHybrid.InitiationResult r = PqHybrid.initiate(bob.publicKey());
        assertEquals(PqHybrid.HANDSHAKE_SIZE, r.handshake.length);
        assertArrayEquals(r.sharedKey, bob.accept(r.handshake));
    }

    @Test
    public void privateKeySerializationRoundTrips() {
        PqHybrid.HybridPrivateKey bob = PqHybrid.HybridPrivateKey.generate();
        PqHybrid.HybridPrivateKey restored = PqHybrid.HybridPrivateKey.fromBytes(bob.toBytes());
        assertArrayEquals(bob.publicKey().toBytes(), restored.publicKey().toBytes());
        PqHybrid.InitiationResult r = PqHybrid.initiate(bob.publicKey());
        assertArrayEquals(r.sharedKey, restored.accept(r.handshake));
    }

    @Test
    public void rejectsWrongSizes() {
        PqHybrid.HybridPrivateKey bob = PqHybrid.HybridPrivateKey.generate();
        assertThrows(IllegalArgumentException.class, () -> bob.accept(new byte[10]));
        assertThrows(IllegalArgumentException.class, () -> PqHybrid.HybridPublicKey.fromBytes(new byte[10]));
        assertThrows(IllegalArgumentException.class, () -> PqHybrid.HybridPrivateKey.fromBytes(new byte[10]));
    }
}
