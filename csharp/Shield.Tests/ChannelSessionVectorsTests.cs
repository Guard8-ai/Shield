using System;
using System.IO;
using System.Text.Json;
using Xunit;
using Dikestra.Shield;

namespace Shield.Tests
{
    /// <summary>
    /// Conformance: the C# PAKEExchange primitives must satisfy the shared
    /// cross-language vectors (tests/channel_session_vectors.json), proving
    /// PAKE.Derive/Combine are byte-identical to the Rust source of truth (and
    /// therefore to Python/Go/JS). C# has no ShieldChannel, so it anchors the
    /// underlying primitives directly.
    /// </summary>
    public class ChannelSessionVectorsTests
    {
        private static string VectorsPath()
        {
            string dir = AppContext.BaseDirectory;
            for (int i = 0; i < 8 && dir != null; i++)
            {
                string candidate = Path.Combine(dir, "tests", "channel_session_vectors.json");
                if (File.Exists(candidate)) return candidate;
                dir = Directory.GetParent(dir)?.FullName;
            }
            throw new FileNotFoundException("channel_session_vectors.json not found from " + AppContext.BaseDirectory);
        }

        private static byte[] Hex(string h) => Convert.FromHexString(h);
        private static string Hx(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

        [Fact]
        public void PakePrimitivesMatchVectors()
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(VectorsPath()));
            var p = doc.RootElement.GetProperty("pake_primitives");

            string password = p.GetProperty("password").GetString();
            byte[] salt = Hex(p.GetProperty("salt_hex").GetString());
            int iterations = p.GetProperty("iterations").GetInt32();

            foreach (var d in p.GetProperty("derive").EnumerateArray())
            {
                string role = d.GetProperty("role").GetString();
                string expected = d.GetProperty("expected_hex").GetString();
                Assert.Equal(expected, Hx(Exchange.PAKE.Derive(password, salt, role, iterations)));
            }

            foreach (var c in p.GetProperty("combine").EnumerateArray())
            {
                var inputs = c.GetProperty("inputs_hex");
                byte[] a = Hex(inputs[0].GetString());
                byte[] b = Hex(inputs[1].GetString());
                string expected = c.GetProperty("expected_hex").GetString();
                Assert.Equal(expected, Hx(Exchange.PAKE.Combine(a, b)));
            }
        }
    }
}
