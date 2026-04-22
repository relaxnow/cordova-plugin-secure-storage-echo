using System;
using System.Security.Cryptography;
using System.Text;

namespace CryphoSecureStorage
{
    /// <summary>
    /// Minimal logger interface for diagnostic output without external dependencies.
    /// </summary>
    public interface ISimpleLogger
    {
        void LogDebug(string message);
        void LogWarning(string message);
        void LogError(string message);
    }

    /// <summary>
    /// No-op logger implementation that discards messages.
    /// </summary>
    public class NullLogger : ISimpleLogger
    {
        public void LogDebug(string message) { }
        public void LogWarning(string message) { }
        public void LogError(string message) { }
    }

    /// <summary>
    /// Legacy cipher deprecation helper.
    /// Tracks the cutoff date for PKCS1 cipher support (July 1st, 2026).
    /// </summary>
    internal static class LegacyCipherDeprecation
    {
        /// <summary>
        /// The date after which legacy PKCS1 cipher support is no longer available.
        /// </summary>
        private static readonly DateTime DeprecationDate = new DateTime(2026, 7, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Checks if legacy PKCS1 cipher support has been deprecated.
        /// </summary>
        /// <returns>true if current UTC date is on or after July 1st, 2026</returns>
        public static bool IsDeprecated => DateTime.UtcNow >= DeprecationDate;

        /// <summary>
        /// Gets the deprecation date as a formatted string.
        /// </summary>
        public static string DeprecationDateString => DeprecationDate.ToString("yyyy-MM-dd");
    }

    /// <summary>
    /// RSA encryption helper that encrypts with secure OAEP padding
    /// and transparently decrypts both new OAEP and legacy PKCS1 encrypted data.
    /// 
    /// Mirrors the Android implementation in AbstractRSA.java for server-side decryption.
    /// Implements IDisposable for proper resource cleanup of RSA key material.
    /// </summary>
    public class RSAEncryptionHelper : IDisposable
    {
        private readonly ISimpleLogger _logger;
        
        private readonly RSA _publicKey;
        private readonly RSA _privateKey;
        private bool _disposed = false;

        /// <summary>
        /// Initialize with RSA key and optional logger for diagnostics.
        /// </summary>
        public RSAEncryptionHelper(RSA key, ISimpleLogger logger = null)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            
            // Validate minimum key size (2048-bit is minimum, 3072+ recommended)
            if (key.KeySize < 2048)
                throw new ArgumentException(
                    $"RSA key must be at least 2048 bits. Current: {key.KeySize}", 
                    nameof(key));
            
            _publicKey = key;
            _privateKey = key;
            _logger = logger ?? new NullLogger();
            
            _logger.LogDebug($"RSAEncryptionHelper initialized with {key.KeySize}-bit RSA key");
        }

        /// <summary>
        /// Dispose unmanaged resources and RSA key material.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Protected dispose implementation following the IDisposable pattern.
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources
                    _publicKey?.Dispose();
                    _privateKey?.Dispose();
                    _logger.LogDebug("RSAEncryptionHelper resources disposed");
                }
                _disposed = true;
            }
        }

        /// <summary>
        /// Finalizer to ensure RSA key material is cleaned up even if Dispose is not called.
        /// </summary>
        ~RSAEncryptionHelper()
        {
            Dispose(false);
        }

        /// <summary>
        /// Ensures the object has not been disposed before operations.
        /// </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(RSAEncryptionHelper), "Cannot use disposed RSAEncryptionHelper instance");
        }

        /// <summary>
        /// Encrypt data using secure OAEP padding with SHA-256.
        /// Matches the Android implementation for consistency.
        /// </summary>
        public byte[] Encrypt(byte[] plainText)
        {
            ThrowIfDisposed();
            
            if (plainText == null || plainText.Length == 0)
                throw new ArgumentException("Plain text cannot be null or empty.", nameof(plainText));

            try
            {
                // Use OAEP with SHA-256 for secure encryption (Veracode compliant)
                return _publicKey.Encrypt(plainText, RSAEncryptionPadding.OaepSHA256);
            }
            catch (Exception ex)
            {
                _logger.LogError($"RSA encryption failed: {ex.Message}");
                throw new CryptographicException("RSA encryption failed.", ex);
            }
        }

        /// <summary>
        /// Decrypt data with transparent format detection and security logging.
        /// Tries OAEP first (new format), then falls back to PKCS1 (legacy format).
        /// Legacy PKCS1 support is deprecated as of July 1st, 2026.
        /// </summary>
        public byte[] Decrypt(byte[] encryptedText)
        {
            ThrowIfDisposed();
            
            if (encryptedText == null || encryptedText.Length == 0)
                throw new ArgumentException("Encrypted text cannot be null or empty.", nameof(encryptedText));

            // Try OAEP first (new format)
            try
            {
                byte[] decrypted = _privateKey.Decrypt(encryptedText, RSAEncryptionPadding.OaepSHA256);
                _logger.LogDebug("Successfully decrypted data using OAEP-SHA256 padding");
                return decrypted;
            }
            catch (CryptographicException oaepException)
            {
                // Check if legacy PKCS1 support has been deprecated
                if (LegacyCipherDeprecation.IsDeprecated)
                {
                    _logger.LogError($"Legacy PKCS1 cipher support was deprecated on {LegacyCipherDeprecation.DeprecationDateString}. Cannot decrypt legacy data.");
                    throw new CryptographicException(
                        $"Legacy PKCS1 cipher support was deprecated on {LegacyCipherDeprecation.DeprecationDateString}. " +
                        "Please update all encrypted data to use OAEP padding. " +
                        $"Original error: {oaepException.Message}",
                        oaepException);
                }

                _logger.LogWarning("OAEP-SHA256 decryption failed, attempting legacy PKCS1 fallback");
                
                // OAEP failed and legacy support still active, try PKCS1 padding
                try
                {
                    byte[] decrypted = _privateKey.Decrypt(encryptedText, RSAEncryptionPadding.Pkcs1);
                    _logger.LogWarning("Successfully decrypted data using legacy PKCS1 padding - consider re-encrypting with OAEP");
                    return decrypted;
                }
                catch (CryptographicException)
                {
                    // Both failed - log security event and throw original OAEP exception
                    _logger.LogError($"Decryption failed with both OAEP and PKCS1 padding. Possible tampering or corrupt data. Error: {oaepException.Message}");
                    throw new CryptographicException(
                        "Failed to decrypt data. Tried OAEP (SHA-256) and PKCS1 padding formats. Data may be corrupted or tampered.",
                        oaepException);
                }
            }
        }

        /// <summary>
        /// Decrypt data and return as UTF-8 string.
        /// Useful for text-based encrypted content.
        /// </summary>
        /// <exception cref="CryptographicException">Thrown if decryption returns empty data</exception>
        public string DecryptAsString(byte[] encryptedText)
        {
            ThrowIfDisposed();
            
            byte[] decrypted = Decrypt(encryptedText);
            if (decrypted == null || decrypted.Length == 0)
                throw new CryptographicException("Decryption returned empty data. Cannot convert to string.");
            
            return Encoding.UTF8.GetString(decrypted);
        }

        /// <summary>
        /// Encrypt string data using UTF-8 encoding.
        /// </summary>
        public byte[] EncryptString(string plainText)
        {
            ThrowIfDisposed();
            
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentException("Plain text cannot be null or empty.", nameof(plainText));

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            return Encrypt(plainBytes);
        }
    }

    /// <summary>
    /// Example usage demonstrating encryption/decryption with the RSAEncryptionHelper.
    /// 
    /// NOTE: This example is for documentation purposes only.
    /// 
    /// In production:
    /// - Load RSA keys from secure sources (HSM, Azure Key Vault, AWS KMS, etc.)
    /// - Never hardcode or generate keys in application code
    /// - Always use 'using' statements or IDisposable pattern for proper cleanup
    /// - Monitor logs for decryption failures and fallback usage
    /// - Plan migration of legacy PKCS1-encrypted data to OAEP format
    /// </summary>
    public class RSAEncryptionExample
    {
        /// <summary>
        /// Production example showing proper resource management.
        /// Replace key loading logic with your secure key store implementation.
        /// </summary>
        public static void ProductionExample()
        {
            // TODO: Replace with actual key loading from secure source
            // Example with Azure Key Vault, AWS KMS, or HSM
            RSA rsaKey = LoadKeyFromSecureSource(); // Your implementation
            
            try
            {
                // Always use 'using' to ensure proper resource cleanup
                using (var helper = new RSAEncryptionHelper(rsaKey))
                {
                    // Example 1: Encrypt sensitive data
                    string originalText = "Sensitive data to encrypt";
                    byte[] encrypted = helper.EncryptString(originalText);
                    Console.WriteLine($"Encrypted: {Convert.ToBase64String(encrypted)}");

                    // Example 2: Decrypt data with transparent fallback
                    string decrypted = helper.DecryptAsString(encrypted);
                    Console.WriteLine($"Decrypted: {decrypted}");
                    Console.WriteLine($"Match: {originalText == decrypted}");
                }
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine($"Cryptographic error: {ex.Message}");
                // Log to monitoring/alerting system
            }
            catch (ObjectDisposedException ex)
            {
                Console.WriteLine($"Resource error: {ex.Message}");
            }
        }

        /// <summary>
        /// Placeholder for secure key loading implementation.
        /// Replace with actual logic for your environment.
        /// </summary>
        private static RSA LoadKeyFromSecureSource()
        {
            // Example implementations:
            // - Azure Key Vault: new KeyVaultKeyProvider().GetKey("key-name")
            // - AWS KMS: new AmazonKeyManagementServiceClient().DecryptAsync(...)
            // - HSM: new HsmProvider().LoadKey(...)
            // - Certificates: X509Store.Open() and cert.GetRSAPrivateKey()
            
            throw new NotImplementedException("Implement key loading from your secure source");
        }
    }
}
