using System;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using Xunit;
using Dikestra.Shield;

namespace Shield.Tests
{
    public class StreamCipherEofTests
    {
        // Cross-language golden vector for the authenticated end-of-stream tag.
        //   master_key  = 32 x 0x42
        //   stream_salt = 16 x 0x01
        //   chunk_count = 3
        private const string ExpectedTagHex =
            "52d4dfbeccc364bd69a2f232aa460bd1eb79b0c93903f344dd7b937703918431";

        private static byte[] ComputeEofTag(byte[] key, byte[] salt, ulong count)
        {
            var m = typeof(StreamCipher).GetMethod(
                "ComputeEofTag", BindingFlags.NonPublic | BindingFlags.Static);
            return (byte[])m.Invoke(null, new object[] { key, salt, count });
        }

        private static string ToHex(byte[] b) =>
            string.Concat(b.Select(x => x.ToString("x2")));

        [Fact]
        public void TestEofTagConformanceVector()
        {
            byte[] key = Enumerable.Repeat((byte)0x42, 32).ToArray();
            byte[] salt = Enumerable.Repeat((byte)0x01, 16).ToArray();
            byte[] tag = ComputeEofTag(key, salt, 3);
            Assert.Equal(ExpectedTagHex, ToHex(tag));
        }

        [Fact]
        public void TestStreamRoundtrip()
        {
            byte[] key = Enumerable.Repeat((byte)0x42, 32).ToArray();
            using var cipher = new StreamCipher(key, 16);
            byte[] data = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
            byte[] enc = cipher.Encrypt(data);
            Assert.Equal(data, cipher.Decrypt(enc));
        }

        [Fact]
        public void TestTruncationAtChunkBoundaryRejected()
        {
            byte[] key = Enumerable.Repeat((byte)0x42, 32).ToArray();
            using var cipher = new StreamCipher(key, 16);
            byte[] data = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
            byte[] enc = cipher.Encrypt(data);

            // Drop the trailing 32-byte EOF tag and the 4-byte zero marker.
            byte[] truncated = enc.Take(enc.Length - 36).ToArray();
            Assert.ThrowsAny<Exception>(() => cipher.Decrypt(truncated));
        }

        [Fact]
        public void TestForgedEndMarkerRejected()
        {
            byte[] key = Enumerable.Repeat((byte)0x42, 32).ToArray();
            using var cipher = new StreamCipher(key, 16);
            byte[] data = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
            byte[] enc = cipher.Encrypt(data);

            // Strip trailer, then re-append a bare zero marker (no valid tag).
            byte[] forged = enc.Take(enc.Length - 36)
                .Concat(new byte[] { 0, 0, 0, 0 }).ToArray();
            Assert.ThrowsAny<Exception>(() => cipher.Decrypt(forged));
        }
    }
}
