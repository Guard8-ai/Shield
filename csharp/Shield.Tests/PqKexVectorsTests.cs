using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Xunit;
using Dikestra.Shield;

namespace Shield.Tests
{
    /// <summary>
    /// Conformance: the C# post-quantum hybrid KEX must satisfy the shared
    /// cross-language vectors (tests/pq_kex_vectors.json), proving byte-identical
    /// key reconstruction and shared-key derivation against Python/Go/Rust/JS.
    /// </summary>
    public class PqKexVectorsTests
    {
        private static string VectorsPath()
        {
            string dir = AppContext.BaseDirectory;
            for (int i = 0; i < 8 && dir != null; i++)
            {
                string candidate = Path.Combine(dir, "tests", "pq_kex_vectors.json");
                if (File.Exists(candidate)) return candidate;
                dir = Directory.GetParent(dir)?.FullName;
            }
            throw new FileNotFoundException("pq_kex_vectors.json not found from " + AppContext.BaseDirectory);
        }

        public static IEnumerable<object[]> AllVectors()
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(VectorsPath()));
            foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
                yield return new object[]
                {
                    v.GetProperty("name").GetString(),
                    v.GetProperty("bob_private_hex").GetString(),
                    v.GetProperty("bob_public_bundle_hex").GetString(),
                    v.GetProperty("handshake_hex").GetString(),
                    v.GetProperty("expected_shared_key_hex").GetString(),
                };
        }

        private static byte[] Hex(string h) => Convert.FromHexString(h);
        private static string Hx(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

        [Theory]
        [MemberData(nameof(AllVectors))]
        public void ReproducesVector(string name, string privHex, string bundleHex, string handshakeHex, string sharedHex)
        {
            var bob = HybridPrivateKey.FromBytes(Hex(privHex));
            Assert.Equal(bundleHex, Hx(bob.PublicKey().ToBytes()));
            var shared = bob.Accept(Hex(handshakeHex));
            Assert.Equal(sharedHex, Hx(shared));
        }

        [Fact]
        public void InitiateAcceptRoundTrips()
        {
            var bob = HybridPrivateKey.Generate();
            var (handshake, aliceKey) = PqHybrid.Initiate(bob.PublicKey());
            Assert.Equal(PqHybrid.HandshakeSize, handshake.Length);
            Assert.Equal(aliceKey, bob.Accept(handshake));
        }

        [Fact]
        public void PrivateKeySerializationRoundTrips()
        {
            var bob = HybridPrivateKey.Generate();
            var restored = HybridPrivateKey.FromBytes(bob.ToBytes());
            Assert.Equal(bob.PublicKey().ToBytes(), restored.PublicKey().ToBytes());
            var (handshake, aliceKey) = PqHybrid.Initiate(bob.PublicKey());
            Assert.Equal(aliceKey, restored.Accept(handshake));
        }

        [Fact]
        public void RejectsWrongSizes()
        {
            var bob = HybridPrivateKey.Generate();
            Assert.Throws<ArgumentException>(() => bob.Accept(new byte[10]));
            Assert.Throws<ArgumentException>(() => HybridPublicKey.FromBytes(new byte[10]));
            Assert.Throws<ArgumentException>(() => HybridPrivateKey.FromBytes(new byte[10]));
        }
    }
}
