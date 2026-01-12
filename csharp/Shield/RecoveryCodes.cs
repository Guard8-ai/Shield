using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Guard8.Shield
{
    /// <summary>
    /// RecoveryCodes - Backup codes for 2FA.
    ///
    /// Use when user loses access to their authenticator app.
    /// Each code can only be used once.
    /// </summary>
    public class RecoveryCodes
    {
        private readonly HashSet<string> _codes;
        private readonly HashSet<string> _used = new();

        /// <summary>
        /// Create with existing codes.
        /// </summary>
        public RecoveryCodes(IEnumerable<string> codes)
        {
            _codes = new HashSet<string>(codes);
        }

        /// <summary>
        /// Create with newly generated codes.
        /// </summary>
        public RecoveryCodes() : this(GenerateCodes(10, 8))
        {
        }

        /// <summary>
        /// Generate recovery codes.
        /// </summary>
        /// <param name="count">Number of codes to generate</param>
        /// <param name="length">Length of each code (must be even)</param>
        /// <returns>List of formatted codes (XXXX-XXXX)</returns>
        public static List<string> GenerateCodes(int count = 10, int length = 8)
        {
            var result = new List<string>();
            using var rng = RandomNumberGenerator.Create();

            for (int i = 0; i < count; i++)
            {
                byte[] bytes = new byte[length / 2];
                rng.GetBytes(bytes);

                string code = BitConverter.ToString(bytes).Replace("-", "").ToUpper();
                // Format as XXXX-XXXX
                string formatted = $"{code[..4]}-{code[4..]}";
                result.Add(formatted);
            }

            return result;
        }

        /// <summary>
        /// Verify and consume a recovery code.
        /// </summary>
        /// <param name="code">Code to verify</param>
        /// <returns>true if valid (code is now consumed)</returns>
        public bool Verify(string code)
        {
            // Normalize format (remove dashes, uppercase)
            string normalized = code.Replace("-", "").ToUpper();
            if (normalized.Length < 8)
                return false;

            string formatted = $"{normalized[..4]}-{normalized[4..8]}";

            if (_used.Contains(formatted))
                return false;

            if (_codes.Contains(formatted))
            {
                _used.Add(formatted);
                _codes.Remove(formatted);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Get remaining (unused) codes.
        /// </summary>
        public IEnumerable<string> RemainingCodes => _codes;

        /// <summary>
        /// Get count of remaining codes.
        /// </summary>
        public int RemainingCount => _codes.Count;

        /// <summary>
        /// Get used codes.
        /// </summary>
        public IEnumerable<string> UsedCodes => _used;
    }
}
