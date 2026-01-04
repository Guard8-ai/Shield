using System;
using System.Security.Cryptography;
using System.Text;

namespace Guard8.Shield
{
    /// <summary>
    /// TOTP - Time-based One-Time Password (RFC 6238)
    /// </summary>
    public class Totp : IDisposable
    {
        public const int DefaultDigits = 6;
        public const int DefaultInterval = 30;
        public const int DefaultSecretSize = 20;

        private readonly byte[] _secret;
        private readonly int _digits;
        private readonly long _interval;
        private bool _disposed;

        public Totp(byte[] secret, int digits = DefaultDigits, int interval = DefaultInterval)
        {
            _secret = new byte[secret.Length];
            Array.Copy(secret, _secret, secret.Length);
            _digits = digits > 0 ? digits : DefaultDigits;
            _interval = interval > 0 ? interval : DefaultInterval;
        }

        public static byte[] GenerateSecret()
        {
            return Shield.RandomBytes(DefaultSecretSize);
        }

        public string Generate(long timestamp = 0)
        {
            if (timestamp == 0)
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            long counter = timestamp / _interval;
            return GenerateHotp(counter);
        }

        public bool Verify(string code, long timestamp = 0, int window = 1)
        {
            if (timestamp == 0)
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (window <= 0)
                window = 1;

            for (int i = 0; i <= window; i++)
            {
                if (Generate(timestamp - i * _interval) == code)
                    return true;
                if (i > 0 && Generate(timestamp + i * _interval) == code)
                    return true;
            }
            return false;
        }

        private string GenerateHotp(long counter)
        {
            byte[] counterBytes = new byte[8];
            for (int i = 7; i >= 0; i--)
            {
                counterBytes[i] = (byte)(counter & 0xff);
                counter >>= 8;
            }

            using var hmac = new HMACSHA1(_secret);
            byte[] hash = hmac.ComputeHash(counterBytes);

            int offset = hash[19] & 0x0f;
            int code = ((hash[offset] & 0x7f) << 24) |
                       ((hash[offset + 1] & 0xff) << 16) |
                       ((hash[offset + 2] & 0xff) << 8) |
                       (hash[offset + 3] & 0xff);

            int modulo = 1;
            for (int i = 0; i < _digits; i++)
                modulo *= 10;

            return code % modulo.ToString().PadLeft(_digits, '0');
        }

        public string ToBase32()
        {
            return Base32Encode(_secret);
        }

        public static Totp FromBase32(string encoded)
        {
            return new Totp(Base32Decode(encoded));
        }

        public string GetProvisioningUri(string account, string issuer)
        {
            string secret = ToBase32();
            return $"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={_digits}&period={_interval}";
        }

        public byte[] GetSecret()
        {
            byte[] copy = new byte[_secret.Length];
            Array.Copy(_secret, copy, _secret.Length);
            return copy;
        }

        private static readonly string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        private static string Base32Encode(byte[] data)
        {
            var result = new StringBuilder();
            int buffer = 0;
            int bufferLength = 0;

            foreach (byte b in data)
            {
                buffer = (buffer << 8) | b;
                bufferLength += 8;
                while (bufferLength >= 5)
                {
                    bufferLength -= 5;
                    result.Append(Base32Alphabet[(buffer >> bufferLength) & 0x1f]);
                }
            }
            if (bufferLength > 0)
                result.Append(Base32Alphabet[(buffer << (5 - bufferLength)) & 0x1f]);

            return result.ToString();
        }

        private static byte[] Base32Decode(string encoded)
        {
            encoded = encoded.ToUpper().TrimEnd('=');
            var result = new byte[encoded.Length * 5 / 8];
            int buffer = 0;
            int bufferLength = 0;
            int index = 0;

            foreach (char c in encoded)
            {
                int val = Base32Alphabet.IndexOf(c);
                if (val < 0) continue;
                buffer = (buffer << 5) | val;
                bufferLength += 5;
                if (bufferLength >= 8)
                {
                    bufferLength -= 8;
                    result[index++] = (byte)((buffer >> bufferLength) & 0xff);
                }
            }

            byte[] trimmed = new byte[index];
            Array.Copy(result, trimmed, index);
            return trimmed;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Shield.SecureWipe(_secret);
                _disposed = true;
            }
        }
    }
}
