using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Xunit;
using Dikestra.Shield;

namespace Shield.Tests
{
    /// <summary>
    /// Conformance: reproduce the Rust-generated v4 vectors byte-for-byte.
    /// Proves the C# binding derives the same master + AEAD keys, reproduces every
    /// deterministic ciphertext BYTE-FOR-BYTE, and decrypts each back to plaintext.
    /// </summary>
    public class V4VectorsTests
    {
        private static string VectorsPath()
        {
            // Walk up from the test bin dir to the repo root, then tests/.
            string dir = AppContext.BaseDirectory;
            for (int i = 0; i < 8 && dir != null; i++)
            {
                string candidate = Path.Combine(dir, "tests", "v4_test_vectors.json");
                if (File.Exists(candidate)) return candidate;
                dir = Directory.GetParent(dir)?.FullName;
            }
            throw new FileNotFoundException("v4_test_vectors.json not found walking up from " + AppContext.BaseDirectory);
        }

        public static IEnumerable<object[]> AllVectors()
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(VectorsPath()));
            var root = doc.RootElement;
            foreach (var v in root.GetProperty("deterministic_vectors").EnumerateArray())
                yield return new object[] { Vec.From(v) };
            if (root.TryGetProperty("deterministic_vectors_chacha", out var cha))
                foreach (var v in cha.EnumerateArray())
                    yield return new object[] { Vec.From(v) };
        }

        public class Vec
        {
            public string Name, Mode, Suite, Password, Service, SaltHex, KeyHex, NonceHex,
                PaddingHex, PlaintextHex, MasterKeyHex, AeadKeyHex, ExpectedOutputHex;
            public int Iterations, PadLen;
            public long TimestampMs;

            public static Vec From(JsonElement v)
            {
                string Get(string k) => v.TryGetProperty(k, out var e) ? e.GetString() : null;
                int GetI(string k) => v.TryGetProperty(k, out var e) ? e.GetInt32() : 0;
                long GetL(string k) => v.TryGetProperty(k, out var e) ? e.GetInt64() : 0;
                return new Vec
                {
                    Name = Get("name"), Mode = Get("mode"), Suite = Get("suite"),
                    Password = Get("password"), Service = Get("service"),
                    SaltHex = Get("salt_hex"), KeyHex = Get("key_hex"),
                    NonceHex = Get("nonce_hex"), PaddingHex = Get("padding_hex"),
                    PlaintextHex = Get("plaintext_hex"), MasterKeyHex = Get("master_key_hex"),
                    AeadKeyHex = Get("aead_key_hex"), ExpectedOutputHex = Get("expected_output_hex"),
                    Iterations = GetI("iterations"), PadLen = GetI("pad_len"),
                    TimestampMs = GetL("timestamp_ms"),
                };
            }
            public override string ToString() => Name;
        }

        private static byte[] Hex(string s) => Convert.FromHexString(s);
        private static byte SuiteByte(Vec v) => v.Suite == "0x02"
            ? Dikestra.Shield.Shield.SuiteChaCha20Poly1305
            : Dikestra.Shield.Shield.SuiteAesGcm;

        private static byte[] MasterFor(Vec v)
        {
            if (v.Mode == "password")
            {
                using var s = new Dikestra.Shield.Shield(v.Password, v.Service, null, Hex(v.SaltHex));
                return s.GetKey();
            }
            return Hex(v.KeyHex);
        }

        [Theory]
        [MemberData(nameof(AllVectors))]
        public void KdfMatches(Vec v)
        {
            byte[] master = MasterFor(v);
            Assert.Equal(v.MasterKeyHex, Convert.ToHexString(master).ToLowerInvariant());
            byte[] aeadKey = Dikestra.Shield.Shield.DeriveAeadKey(master);
            Assert.Equal(v.AeadKeyHex, Convert.ToHexString(aeadKey).ToLowerInvariant());
        }

        [Theory]
        [MemberData(nameof(AllVectors))]
        public void ReproducesBytes(Vec v)
        {
            byte[] aeadKey = Dikestra.Shield.Shield.DeriveAeadKey(MasterFor(v));
            byte[] salt = v.Mode == "password" ? Hex(v.SaltHex) : null;
            byte[] outp = Dikestra.Shield.Shield.SealDeterministic(
                aeadKey, SuiteByte(v), salt, Hex(v.NonceHex), v.TimestampMs,
                v.PadLen, Hex(v.PaddingHex), Hex(v.PlaintextHex));
            Assert.Equal(v.ExpectedOutputHex, Convert.ToHexString(outp).ToLowerInvariant());
        }

        [Theory]
        [MemberData(nameof(AllVectors))]
        public void Decrypts(Vec v)
        {
            byte[] aeadKey = Dikestra.Shield.Shield.DeriveAeadKey(MasterFor(v));
            byte[] encrypted = Hex(v.ExpectedOutputHex);
            int aadLen = v.Mode == "password" ? 2 + Dikestra.Shield.Shield.SaltSize : 2;
            byte[] opened = Dikestra.Shield.Shield.OpenCiphertext(aeadKey, SuiteByte(v), encrypted, aadLen, null);
            Assert.Equal(v.PlaintextHex, Convert.ToHexString(opened).ToLowerInvariant());
        }
    }
}
