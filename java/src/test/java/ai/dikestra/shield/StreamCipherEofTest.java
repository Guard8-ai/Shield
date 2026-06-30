package ai.dikestra.shield;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import java.util.Arrays;

/**
 * Tests for the authenticated end-of-stream tag in StreamCipher.
 */
public class StreamCipherEofTest {

    // Cross-language golden vector:
    //   master_key  = 32 x 0x42, stream_salt = 16 x 0x01, chunk_count = 3
    private static final String EXPECTED_TAG_HEX =
            "52d4dfbeccc364bd69a2f232aa460bd1eb79b0c93903f344dd7b937703918431";

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    private static byte[] computeEofTag(byte[] key, byte[] salt, long count) throws Exception {
        Method m = StreamCipher.class.getDeclaredMethod(
                "computeEofTag", byte[].class, byte[].class, long.class);
        m.setAccessible(true);
        return (byte[]) m.invoke(null, key, salt, count);
    }

    @Test
    void testEofTagConformanceVector() throws Exception {
        byte[] key = new byte[32]; Arrays.fill(key, (byte) 0x42);
        byte[] salt = new byte[16]; Arrays.fill(salt, (byte) 0x01);
        assertEquals(EXPECTED_TAG_HEX, hex(computeEofTag(key, salt, 3L)));
    }

    @Test
    void testStreamRoundtrip() {
        byte[] key = new byte[32]; Arrays.fill(key, (byte) 0x42);
        StreamCipher sc = new StreamCipher(key, 16);
        byte[] data = new byte[64]; for (int i = 0; i < 64; i++) data[i] = (byte) i;
        assertArrayEquals(data, sc.decrypt(sc.encrypt(data)));
    }

    @Test
    void testTruncationAtChunkBoundaryRejected() {
        byte[] key = new byte[32]; Arrays.fill(key, (byte) 0x42);
        StreamCipher sc = new StreamCipher(key, 16);
        byte[] data = new byte[64]; for (int i = 0; i < 64; i++) data[i] = (byte) i;
        byte[] enc = sc.encrypt(data);
        byte[] truncated = Arrays.copyOf(enc, enc.length - 36); // drop marker + tag
        assertThrows(Exception.class, () -> sc.decrypt(truncated));
    }

    @Test
    void testForgedEndMarkerRejected() {
        byte[] key = new byte[32]; Arrays.fill(key, (byte) 0x42);
        StreamCipher sc = new StreamCipher(key, 16);
        byte[] data = new byte[64]; for (int i = 0; i < 64; i++) data[i] = (byte) i;
        byte[] enc = sc.encrypt(data);
        byte[] forged = Arrays.copyOf(enc, enc.length - 36 + 4); // bare zero marker, no tag
        assertThrows(Exception.class, () -> sc.decrypt(forged));
    }
}
