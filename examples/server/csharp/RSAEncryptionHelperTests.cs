using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryphoSecureStorage;

namespace CryphoSecureStorage.Tests
{
    /// <summary>
    /// Comprehensive test suite for RSAEncryptionHelper.
    /// Tests OAEP encryption, legacy PKCS1 fallback decryption, resource management, 
    /// and edge cases for the RSA encryption helper.
    /// </summary>
    [TestClass]
    public class RSAEncryptionHelperTests
    {
        private const int MinKeySize = 2048;
        private const int MaxKeySize = 4096;
        private const int WeakKeySize = 1024;
        private const int LargeDataSize = 100;
        private const int PerformanceIterations = 100;
        private const int PerformanceTimeoutMs = 60000;

        private const string TestData = "Test data";
        private const string SecretMessage = "Secret message";
        private const string SensitiveData = "Sensitive data";
        private const string LegacyTestData = "Legacy encrypted data";
        private const string LegacyTestString = "Legacy encrypted string";
        private const string SpecialCharsText = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?";
        private const string UnicodeText = "Unicode: 你好 🔒 مرحبا";
        private const string PerformanceTestData = "Performance test data";

        private RSA _rsa;
        private RSAEncryptionHelper _helper;

        [TestInitialize]
        public void SetUp()
        {
            _rsa = RSA.Create(MinKeySize);
            _helper = new RSAEncryptionHelper(_rsa);
        }

        [TestCleanup]
        public void TearDown()
        {
            _helper?.Dispose();
            _rsa?.Dispose();
        }

        #region Constructor Tests

        [TestMethod]
        public void Constructor_WithNullKey_ThrowsArgumentNullException()
        {
            var ex = Assert.ThrowsException<ArgumentNullException>(() => new RSAEncryptionHelper(null));
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        public void Constructor_WithWeakKey_ThrowsArgumentException()
        {
            using (var weakRsa = RSA.Create(WeakKeySize))
            {
                var ex = Assert.ThrowsException<ArgumentException>(() => new RSAEncryptionHelper(weakRsa));
                Assert.AreEqual("key", ex.ParamName);
                Assert.IsTrue(ex.Message.Contains("2048"));
            }
        }

        [TestMethod]
        public void Constructor_With2048BitKey_Succeeds()
        {
            using (var rsa = RSA.Create(MinKeySize))
            {
                var helper = new RSAEncryptionHelper(rsa);
                Assert.IsNotNull(helper);
                helper.Dispose();
            }
        }

        [TestMethod]
        public void Constructor_With4096BitKey_Succeeds()
        {
            using (var rsa = RSA.Create(MaxKeySize))
            {
                var helper = new RSAEncryptionHelper(rsa);
                Assert.IsNotNull(helper);
                helper.Dispose();
            }
        }

        #endregion

        #region Encryption Tests

        [TestMethod]
        public void Encrypt_WithValidData_ReturnsEncryptedBytes()
        {
            byte[] plainText = Encoding.UTF8.GetBytes(SecretMessage);
            byte[] encrypted = _helper.Encrypt(plainText);

            Assert.IsNotNull(encrypted);
            Assert.IsTrue(encrypted.Length > 0);
            CollectionAssert.AreNotEqual(plainText, encrypted);
        }

        [TestMethod]
        public void Encrypt_WithNullData_ThrowsArgumentException()
        {
            Assert.ThrowsException<ArgumentException>(() => _helper.Encrypt(null));
        }

        [TestMethod]
        public void Encrypt_WithEmptyData_ThrowsArgumentException()
        {
            Assert.ThrowsException<ArgumentException>(() => _helper.Encrypt(new byte[0]));
        }

        [TestMethod]
        public void EncryptString_WithValidText_ReturnsEncryptedBytes()
        {
            byte[] encrypted = _helper.EncryptString(SensitiveData);
            
            Assert.IsNotNull(encrypted);
            Assert.IsTrue(encrypted.Length > 0);
        }

        [TestMethod]
        public void EncryptString_WithNullText_ThrowsArgumentException()
        {
            Assert.ThrowsException<ArgumentException>(() => _helper.EncryptString(null));
        }

        [TestMethod]
        public void EncryptString_WithEmptyText_ThrowsArgumentException()
        {
            Assert.ThrowsException<ArgumentException>(() => _helper.EncryptString(""));
        }

        #endregion

        #region Decryption Tests - OAEP Format (New)

        [TestMethod]
        public void Decrypt_WithOAEPEncryptedData_ReturnsOriginalData()
        {
            byte[] originalData = Encoding.UTF8.GetBytes(TestData);
            byte[] encrypted = _helper.Encrypt(originalData);
            byte[] decrypted = _helper.Decrypt(encrypted);

            CollectionAssert.AreEqual(originalData, decrypted);
        }

        [TestMethod]
        public void DecryptAsString_WithOAEPEncryptedData_ReturnsOriginalString()
        {
            byte[] encrypted = _helper.EncryptString(SecretMessage);
            string decrypted = _helper.DecryptAsString(encrypted);

            Assert.AreEqual(SecretMessage, decrypted);
        }

        #endregion

        #region Decryption Tests - PKCS1 Fallback (Legacy)

        [TestMethod]
        public void Decrypt_WithPKCS1EncryptedData_FallsBackAndDecrypts()
        {
            byte[] originalData = Encoding.UTF8.GetBytes(LegacyTestData);
            byte[] legacyEncrypted = _rsa.Encrypt(originalData, RSAEncryptionPadding.Pkcs1);
            byte[] decrypted = _helper.Decrypt(legacyEncrypted);

            CollectionAssert.AreEqual(originalData, decrypted);
        }

        [TestMethod]
        public void DecryptAsString_WithPKCS1EncryptedData_FallsBackAndDecrypts()
        {
            byte[] originalData = Encoding.UTF8.GetBytes(LegacyTestString);
            byte[] legacyEncrypted = _rsa.Encrypt(originalData, RSAEncryptionPadding.Pkcs1);
            string decrypted = _helper.DecryptAsString(legacyEncrypted);

            Assert.AreEqual(LegacyTestString, decrypted);
        }

        #endregion

        #region Edge Cases

        [TestMethod]
        public void Decrypt_WithNullData_ThrowsArgumentException()
        {
            Assert.ThrowsException<ArgumentException>(() => _helper.Decrypt(null));
        }

        [TestMethod]
        public void Decrypt_WithEmptyData_ThrowsArgumentException()
        {
            Assert.ThrowsException<ArgumentException>(() => _helper.Decrypt(new byte[0]));
        }

        [TestMethod]
        public void DecryptAsString_WithNullData_ThrowsArgumentException()
        {
            Assert.ThrowsException<ArgumentException>(() => _helper.DecryptAsString(null));
        }

        [TestMethod]
        public void Decrypt_WithCorruptedData_ThrowsCryptographicException()
        {
            byte[] validData = Encoding.UTF8.GetBytes("Test");
            byte[] encrypted = _helper.Encrypt(validData);
            encrypted[0] ^= 0xFF;

            var ex = Assert.ThrowsException<CryptographicException>(() => _helper.Decrypt(encrypted));
            Assert.IsTrue(ex.Message.Contains("Failed to decrypt data"));
        }

        [TestMethod]
        public void EncryptDecrypt_WithLargeData_Succeeds()
        {
            byte[] largeData = new byte[LargeDataSize];
            new Random().NextBytes(largeData);

            byte[] encrypted = _helper.Encrypt(largeData);
            byte[] decrypted = _helper.Decrypt(encrypted);

            CollectionAssert.AreEqual(largeData, decrypted);
        }

        [TestMethod]
        public void EncryptDecrypt_WithSpecialCharacters_Succeeds()
        {
            byte[] encrypted = _helper.EncryptString(SpecialCharsText);
            string decrypted = _helper.DecryptAsString(encrypted);

            Assert.AreEqual(SpecialCharsText, decrypted);
        }

        [TestMethod]
        public void EncryptDecrypt_WithUnicode_Succeeds()
        {
            byte[] encrypted = _helper.EncryptString(UnicodeText);
            string decrypted = _helper.DecryptAsString(encrypted);

            Assert.AreEqual(UnicodeText, decrypted);
        }

        #endregion

        #region Disposal Tests

        [TestMethod]
        public void Dispose_FreesResources()
        {
            using (var rsa = RSA.Create(MinKeySize))
            {
                var helper = new RSAEncryptionHelper(rsa);
                helper.Dispose();

                var ex = Assert.ThrowsException<ObjectDisposedException>(
                    () => helper.EncryptString("Test"));
                Assert.AreEqual("RSAEncryptionHelper", ex.ObjectName);
            }
        }

        [TestMethod]
        public void MultipleCalls_BeforeDispose_Succeed()
        {
            string data1 = "First message";
            string data2 = "Second message";
            string data3 = "Third message";

            byte[] enc1 = _helper.EncryptString(data1);
            byte[] enc2 = _helper.EncryptString(data2);
            byte[] enc3 = _helper.EncryptString(data3);

            string dec1 = _helper.DecryptAsString(enc1);
            string dec2 = _helper.DecryptAsString(enc2);
            string dec3 = _helper.DecryptAsString(enc3);

            Assert.AreEqual(data1, dec1);
            Assert.AreEqual(data2, dec2);
            Assert.AreEqual(data3, dec3);
        }

        #endregion

        #region Integration Tests

        [TestMethod]
        public void RealWorldScenario_EncryptDecryptMultipleFormats()
        {
            string newData = "New secure data";
            string legacyData = "Legacy encrypted data";

            byte[] newEncrypted = _helper.EncryptString(newData);
            byte[] legacyEncrypted = _rsa.Encrypt(
                Encoding.UTF8.GetBytes(legacyData),
                RSAEncryptionPadding.Pkcs1);

            string newDecrypted = _helper.DecryptAsString(newEncrypted);
            string legacyDecrypted = _helper.DecryptAsString(legacyEncrypted);

            Assert.AreEqual(newData, newDecrypted);
            Assert.AreEqual(legacyData, legacyDecrypted);
        }

        [TestMethod]
        public void Migration_Scenario_ReencryptLegacyData()
        {
            string originalData = "Data that was encrypted with PKCS1";
            
            byte[] legacyEncrypted = _rsa.Encrypt(
                Encoding.UTF8.GetBytes(originalData),
                RSAEncryptionPadding.Pkcs1);

            string decryptedData = _helper.DecryptAsString(legacyEncrypted);
            byte[] newEncrypted = _helper.EncryptString(decryptedData);
            string finalData = _helper.DecryptAsString(newEncrypted);

            Assert.AreEqual(originalData, decryptedData);
            Assert.AreEqual(originalData, finalData);
        }

        #endregion

        #region Performance Tests

        [TestMethod]
        public void Performance_Encrypt_100Iterations()
        {
            byte[] data = Encoding.UTF8.GetBytes(PerformanceTestData);
            var sw = System.Diagnostics.Stopwatch.StartNew();

            for (int i = 0; i < PerformanceIterations; i++)
            {
                _helper.Encrypt(data);
            }
            sw.Stop();

            Assert.IsTrue(
                sw.ElapsedMilliseconds < PerformanceTimeoutMs,
                $"Encryption performance degraded: {sw.ElapsedMilliseconds}ms for {PerformanceIterations} iterations");
        }

        [TestMethod]
        public void Performance_Decrypt_100Iterations()
        {
            byte[] data = Encoding.UTF8.GetBytes(PerformanceTestData);
            byte[] encrypted = _helper.Encrypt(data);
            var sw = System.Diagnostics.Stopwatch.StartNew();

            for (int i = 0; i < PerformanceIterations; i++)
            {
                _helper.Decrypt(encrypted);
            }
            sw.Stop();

            Assert.IsTrue(
                sw.ElapsedMilliseconds < PerformanceTimeoutMs,
                $"Decryption performance degraded: {sw.ElapsedMilliseconds}ms for {PerformanceIterations} iterations");
        }

        #endregion
    }
}
