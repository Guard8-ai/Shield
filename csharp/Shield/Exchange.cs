using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Guard8.Shield
{
    /// <summary>
    /// Key Exchange - Key exchange without public-key crypto.
    ///
    /// Methods:
    /// 1. PAKE: Password-Authenticated Key Exchange
    /// 2. QR: QR codes, base64 for manual exchange
    /// 3. Key Splitting: XOR-based secret sharing
    /// </summary>
    public static class Exchange
    {
        /// <summary>
        /// Password-Authenticated Key Exchange.
        ///
        /// Both parties derive a shared key from a common password.
        /// Uses role binding to prevent reflection attacks.
        /// </summary>
        public static class PAKE
        {
            public const int DefaultIterations = 200000;

            /// <summary>
            /// Derive key contribution from password.
            /// </summary>
            /// <param name="password">Shared password between parties</param>
            /// <param name="salt">Public salt (can be exchanged openly)</param>
            /// <param name="role">Role identifier ('alice', 'bob', 'initiator', etc.)</param>
            /// <param name="iterations">PBKDF2 iterations (default: 200000)</param>
            /// <returns>32-byte key contribution</returns>
            public static byte[] Derive(string password, byte[] salt, string role, int iterations = 200000)
            {
                using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
                byte[] baseKey = pbkdf2.GetBytes(32);

                using var sha256 = SHA256.Create();
                byte[] roleBytes = Encoding.UTF8.GetBytes(role);
                byte[] combined = baseKey.Concat(roleBytes).ToArray();
                return sha256.ComputeHash(combined);
            }

            /// <summary>
            /// Combine key contributions into session key.
            /// </summary>
            /// <param name="contributions">Key contributions from all parties</param>
            /// <returns>32-byte shared session key</returns>
            public static byte[] Combine(params byte[][] contributions)
            {
                // Sort contributions for deterministic output
                var sorted = contributions.OrderBy(b => Convert.ToHexString(b)).ToArray();

                using var sha256 = SHA256.Create();
                byte[] combined = sorted.SelectMany(b => b).ToArray();
                return sha256.ComputeHash(combined);
            }

            /// <summary>
            /// Generate random salt for key exchange.
            /// </summary>
            public static byte[] GenerateSalt()
            {
                return Shield.RandomBytes(16);
            }
        }

        /// <summary>
        /// Key exchange via QR codes or manual transfer.
        ///
        /// Encodes keys in URL-safe base64 for easy scanning/typing.
        /// </summary>
        public static class QR
        {
            /// <summary>
            /// Encode key for QR code or manual transfer.
            /// </summary>
            /// <param name="key">Key bytes to encode</param>
            /// <returns>URL-safe base64 string</returns>
            public static string Encode(byte[] key)
            {
                return Convert.ToBase64String(key).Replace('+', '-').Replace('/', '_').TrimEnd('=');
            }

            /// <summary>
            /// Decode key from QR code or manual input.
            /// </summary>
            /// <param name="encoded">Base64 string from Encode()</param>
            /// <returns>Key bytes</returns>
            public static byte[] Decode(string encoded)
            {
                // Restore standard base64 chars and padding
                string base64 = encoded.Replace('-', '+').Replace('_', '/');
                switch (base64.Length % 4)
                {
                    case 2: base64 += "=="; break;
                    case 3: base64 += "="; break;
                }
                return Convert.FromBase64String(base64);
            }

            /// <summary>
            /// Generate complete exchange data with optional metadata.
            /// </summary>
            /// <param name="key">Key to exchange</param>
            /// <param name="metadata">Optional metadata (issuer, expiry, etc.)</param>
            /// <returns>JSON-like string for QR code</returns>
            public static string GenerateExchangeData(byte[] key, Dictionary<string, object> metadata = null)
            {
                var data = new Dictionary<string, object>
                {
                    ["v"] = 1,
                    ["k"] = Encode(key)
                };

                if (metadata != null && metadata.Count > 0)
                {
                    data["m"] = metadata;
                }

                return JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = false });
            }

            /// <summary>
            /// Parse exchange data from QR code.
            /// </summary>
            /// <param name="data">JSON string from GenerateExchangeData()</param>
            /// <returns>Tuple of (key, metadata)</returns>
            public static (byte[] Key, Dictionary<string, object> Metadata) ParseExchangeData(string data)
            {
                var doc = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(data);
                string keyB64 = doc["k"].GetString();
                byte[] key = Decode(keyB64);

                Dictionary<string, object> metadata = null;
                if (doc.ContainsKey("m"))
                {
                    metadata = new Dictionary<string, object>();
                    foreach (var prop in doc["m"].EnumerateObject())
                    {
                        metadata[prop.Name] = prop.Value.ValueKind switch
                        {
                            JsonValueKind.String => prop.Value.GetString(),
                            JsonValueKind.Number => prop.Value.GetInt64(),
                            JsonValueKind.True => true,
                            JsonValueKind.False => false,
                            _ => prop.Value.ToString()
                        };
                    }
                }

                return (key, metadata);
            }
        }

        /// <summary>
        /// Split keys into shares for threshold recovery.
        ///
        /// This is a simplified XOR-based scheme where ALL shares
        /// are required for reconstruction.
        /// </summary>
        public static class KeySplitter
        {
            /// <summary>
            /// Split key into shares (all required for reconstruction).
            /// </summary>
            /// <param name="key">Key to split</param>
            /// <param name="numShares">Number of shares to create</param>
            /// <returns>List of shares</returns>
            public static List<byte[]> Split(byte[] key, int numShares)
            {
                if (numShares < 2)
                    throw new ArgumentException("Need at least 2 shares");

                var shares = new List<byte[]>();

                // Generate random shares for all but the last
                for (int i = 0; i < numShares - 1; i++)
                {
                    shares.Add(Shield.RandomBytes(key.Length));
                }

                // Final share = XOR of key with all other shares
                byte[] finalShare = (byte[])key.Clone();
                foreach (var share in shares)
                {
                    for (int i = 0; i < finalShare.Length; i++)
                    {
                        finalShare[i] ^= share[i];
                    }
                }
                shares.Add(finalShare);

                return shares;
            }

            /// <summary>
            /// Combine shares to recover key.
            /// </summary>
            /// <param name="shares">All shares from Split()</param>
            /// <returns>Original key</returns>
            public static byte[] Combine(List<byte[]> shares)
            {
                if (shares.Count < 2)
                    throw new ArgumentException("Need at least 2 shares");

                byte[] result = (byte[])shares[0].Clone();
                for (int i = 1; i < shares.Count; i++)
                {
                    for (int j = 0; j < result.Length; j++)
                    {
                        result[j] ^= shares[i][j];
                    }
                }

                return result;
            }
        }
    }
}
