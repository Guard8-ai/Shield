using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Guard8.Shield
{
    /// <summary>
    /// User identity.
    /// </summary>
    public class Identity
    {
        public string UserId { get; }
        public string DisplayName { get; }
        public byte[] VerificationKey { get; }
        public long CreatedAt { get; }
        public Dictionary<string, object> Attributes { get; }

        public Identity(string userId, string displayName, byte[] verificationKey,
                        long createdAt, Dictionary<string, object> attributes = null)
        {
            UserId = userId;
            DisplayName = displayName;
            VerificationKey = verificationKey;
            CreatedAt = createdAt;
            Attributes = attributes ?? new Dictionary<string, object>();
        }
    }

    /// <summary>
    /// Session information from validated token.
    /// </summary>
    public class Session
    {
        public string UserId { get; }
        public long Created { get; }
        public long Expires { get; }
        public List<string> Permissions { get; }
        public Dictionary<string, object> Metadata { get; }

        public Session(string userId, long created, long expires,
                       List<string> permissions = null, Dictionary<string, object> metadata = null)
        {
            UserId = userId;
            Created = created;
            Expires = expires;
            Permissions = permissions ?? new List<string>();
            Metadata = metadata ?? new Dictionary<string, object>();
        }

        public bool IsExpired => DateTimeOffset.UtcNow.ToUnixTimeSeconds() > Expires;

        public long RemainingTime => Math.Max(0, Expires - DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    /// <summary>
    /// IdentityProvider - SSO/Identity Provider using symmetric crypto.
    ///
    /// Provides user registration, session management, and service tokens
    /// using only symmetric cryptography (no public-key certificates).
    /// </summary>
    public class IdentityProvider
    {
        private const int PBKDF2_ITERATIONS = 100000;

        private readonly byte[] _providerKey;
        private readonly int _tokenTtl;
        private readonly Dictionary<string, Identity> _identities = new();

        /// <summary>
        /// Create identity provider.
        /// </summary>
        /// <param name="providerKey">32-byte provider secret key</param>
        /// <param name="tokenTtl">Default token lifetime in seconds</param>
        public IdentityProvider(byte[] providerKey, int tokenTtl = 3600)
        {
            _providerKey = (byte[])providerKey.Clone();
            _tokenTtl = tokenTtl > 0 ? tokenTtl : 3600;
        }

        /// <summary>
        /// Register new user identity.
        /// </summary>
        /// <param name="userId">Unique user identifier</param>
        /// <param name="password">User's password</param>
        /// <param name="displayName">User's display name</param>
        /// <param name="attributes">Optional user attributes</param>
        /// <returns>Created identity</returns>
        public Identity Register(string userId, string password, string displayName,
                                 Dictionary<string, object> attributes = null)
        {
            if (_identities.ContainsKey(userId))
                throw new ArgumentException($"User {userId} already exists");

            byte[] verificationKey = DeriveVerificationKey(userId, password);
            var identity = new Identity(
                userId,
                displayName,
                verificationKey,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                attributes
            );

            _identities[userId] = identity;
            return identity;
        }

        /// <summary>
        /// Authenticate user and return session token.
        /// </summary>
        /// <param name="userId">User identifier</param>
        /// <param name="password">User's password</param>
        /// <param name="permissions">Optional permission list</param>
        /// <param name="ttl">Token lifetime (or default if null)</param>
        /// <returns>Session token, or null if authentication fails</returns>
        public string Authenticate(string userId, string password,
                                   List<string> permissions = null, int? ttl = null)
        {
            if (!_identities.TryGetValue(userId, out var identity))
                return null;

            byte[] verificationKey = DeriveVerificationKey(userId, password);
            if (!Shield.ConstantTimeEquals(verificationKey, identity.VerificationKey, 32))
                return null;

            int actualTtl = ttl ?? _tokenTtl;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            var sessionData = new Dictionary<string, object>
            {
                ["user_id"] = userId,
                ["created"] = now,
                ["expires"] = now + actualTtl,
                ["permissions"] = permissions ?? new List<string>(),
                ["nonce"] = GenerateNonce()
            };

            return SignToken(sessionData);
        }

        /// <summary>
        /// Validate session token.
        /// </summary>
        /// <param name="token">Session token from Authenticate()</param>
        /// <returns>Session object, or null if invalid/expired</returns>
        public Session ValidateToken(string token)
        {
            var sessionData = VerifyToken(token);
            if (sessionData == null)
                return null;

            long expires = GetLong(sessionData, "expires");
            if (expires < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                return null;

            var permissions = GetStringList(sessionData, "permissions");
            var metadata = GetDict(sessionData, "metadata");

            return new Session(
                sessionData["user_id"].ToString(),
                GetLong(sessionData, "created"),
                expires,
                permissions,
                metadata
            );
        }

        /// <summary>
        /// Create service-specific access token.
        /// </summary>
        /// <param name="sessionToken">Valid session token</param>
        /// <param name="service">Target service identifier</param>
        /// <param name="permissions">Scoped permissions for this service</param>
        /// <param name="ttl">Token lifetime (default 300 seconds)</param>
        /// <returns>Service token, or null if session invalid</returns>
        public string CreateServiceToken(string sessionToken, string service,
                                         List<string> permissions = null, int ttl = 300)
        {
            var session = ValidateToken(sessionToken);
            if (session == null)
                return null;

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var serviceData = new Dictionary<string, object>
            {
                ["user_id"] = session.UserId,
                ["service"] = service,
                ["created"] = now,
                ["expires"] = now + ttl,
                ["permissions"] = permissions ?? new List<string>(),
                ["parent_expires"] = session.Expires
            };

            return SignToken(serviceData);
        }

        /// <summary>
        /// Validate service-specific token.
        /// </summary>
        /// <param name="token">Service token</param>
        /// <param name="service">Expected service identifier</param>
        /// <returns>Session object, or null if invalid</returns>
        public Session ValidateServiceToken(string token, string service)
        {
            var tokenData = VerifyToken(token);
            if (tokenData == null)
                return null;

            if (tokenData["service"]?.ToString() != service)
                return null;

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long expires = GetLong(tokenData, "expires");
            if (expires < now)
                return null;

            if (tokenData.ContainsKey("parent_expires"))
            {
                long parentExpires = GetLong(tokenData, "parent_expires");
                if (parentExpires < now)
                    return null;
            }

            var permissions = GetStringList(tokenData, "permissions");
            var metadata = new Dictionary<string, object> { ["service"] = service };

            return new Session(
                tokenData["user_id"].ToString(),
                GetLong(tokenData, "created"),
                expires,
                permissions,
                metadata
            );
        }

        /// <summary>
        /// Refresh session token.
        /// </summary>
        /// <param name="token">Current valid session token</param>
        /// <param name="ttl">New lifetime (or default if null)</param>
        /// <returns>New session token, or null if current token invalid</returns>
        public string RefreshToken(string token, int? ttl = null)
        {
            var session = ValidateToken(token);
            if (session == null)
                return null;

            int actualTtl = ttl ?? _tokenTtl;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            var sessionData = new Dictionary<string, object>
            {
                ["user_id"] = session.UserId,
                ["created"] = now,
                ["expires"] = now + actualTtl,
                ["permissions"] = session.Permissions,
                ["nonce"] = GenerateNonce()
            };

            return SignToken(sessionData);
        }

        /// <summary>
        /// Revoke user identity.
        /// </summary>
        /// <param name="userId">User to revoke</param>
        /// <returns>true if user was revoked</returns>
        public bool RevokeUser(string userId)
        {
            return _identities.Remove(userId);
        }

        /// <summary>
        /// Get identity by user ID.
        /// </summary>
        public Identity GetIdentity(string userId)
        {
            return _identities.TryGetValue(userId, out var identity) ? identity : null;
        }

        // Private helpers

        private byte[] DeriveVerificationKey(string userId, string password)
        {
            using var sha256 = SHA256.Create();
            byte[] salt = sha256.ComputeHash(Encoding.UTF8.GetBytes($"user:{userId}"));

            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, PBKDF2_ITERATIONS, HashAlgorithmName.SHA256);
            byte[] userKey = pbkdf2.GetBytes(32);

            byte[] verifyInput = Encoding.UTF8.GetBytes("verify:").Concat(userKey).ToArray();
            return sha256.ComputeHash(verifyInput);
        }

        private string SignToken(Dictionary<string, object> data)
        {
            string json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = false });
            byte[] tokenBytes = Encoding.UTF8.GetBytes(json);

            using var hmac = new HMACSHA256(_providerKey);
            byte[] fullMac = hmac.ComputeHash(tokenBytes);
            byte[] truncatedMac = fullMac.Take(16).ToArray();

            byte[] result = new byte[tokenBytes.Length + 16];
            Array.Copy(tokenBytes, 0, result, 0, tokenBytes.Length);
            Array.Copy(truncatedMac, 0, result, tokenBytes.Length, 16);

            return Convert.ToBase64String(result).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }

        private Dictionary<string, object> VerifyToken(string token)
        {
            try
            {
                // Restore base64 padding and URL-safe chars
                token = token.Replace('-', '+').Replace('_', '/');
                switch (token.Length % 4)
                {
                    case 2: token += "=="; break;
                    case 3: token += "="; break;
                }

                byte[] decoded = Convert.FromBase64String(token);
                if (decoded.Length < 17)
                    return null;

                byte[] tokenBytes = decoded.Take(decoded.Length - 16).ToArray();
                byte[] receivedMac = decoded.Skip(decoded.Length - 16).ToArray();

                using var hmac = new HMACSHA256(_providerKey);
                byte[] fullExpectedMac = hmac.ComputeHash(tokenBytes);
                byte[] expectedMac = fullExpectedMac.Take(16).ToArray();

                if (!Shield.ConstantTimeEquals(receivedMac, expectedMac, 16))
                    return null;

                string json = Encoding.UTF8.GetString(tokenBytes);
                var doc = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);

                var result = new Dictionary<string, object>();
                foreach (var kvp in doc)
                {
                    result[kvp.Key] = JsonElementToObject(kvp.Value);
                }
                return result;
            }
            catch
            {
                return null;
            }
        }

        private object JsonElementToObject(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.String:
                    return element.GetString();
                case JsonValueKind.Number:
                    return element.GetInt64();
                case JsonValueKind.True:
                    return true;
                case JsonValueKind.False:
                    return false;
                case JsonValueKind.Null:
                    return null;
                case JsonValueKind.Array:
                    var list = new List<object>();
                    foreach (var item in element.EnumerateArray())
                        list.Add(JsonElementToObject(item));
                    return list;
                case JsonValueKind.Object:
                    var dict = new Dictionary<string, object>();
                    foreach (var prop in element.EnumerateObject())
                        dict[prop.Name] = JsonElementToObject(prop.Value);
                    return dict;
                default:
                    return element.ToString();
            }
        }

        private string GenerateNonce()
        {
            byte[] bytes = Shield.RandomBytes(8);
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        private long GetLong(Dictionary<string, object> dict, string key)
        {
            if (!dict.TryGetValue(key, out var value))
                return 0;
            return Convert.ToInt64(value);
        }

        private List<string> GetStringList(Dictionary<string, object> dict, string key)
        {
            if (!dict.TryGetValue(key, out var value))
                return new List<string>();
            if (value is List<object> objList)
                return objList.Select(o => o?.ToString() ?? "").ToList();
            if (value is List<string> strList)
                return strList;
            return new List<string>();
        }

        private Dictionary<string, object> GetDict(Dictionary<string, object> dict, string key)
        {
            if (!dict.TryGetValue(key, out var value))
                return new Dictionary<string, object>();
            if (value is Dictionary<string, object> d)
                return d;
            return new Dictionary<string, object>();
        }
    }
}
