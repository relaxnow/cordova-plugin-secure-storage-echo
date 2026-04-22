package com.crypho.plugins;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyProperties;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;

public abstract class AbstractRSA {
    protected static final String TAG = "SecureStorage";
    static final Integer CERT_VALID_YEARS = 100;
    static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    
    // Legacy PKCS1 cipher support deprecated as of July 1st, 2026
    // After this date, only OAEP padding will be accepted for decryption
    private static final long LEGACY_CIPHER_DEPRECATION_DATE_MILLIS = getLegacyDeprecationDate();
    
    // Cipher for encryption with secure OAEP padding
    private final Cipher CIPHER_ENCRYPT = getCipherEncrypt();
    // Cipher for decryption with OAEP (new format)
    private final Cipher CIPHER_DECRYPT_OAEP = getCipherDecryptOAEP();
    // Cipher for decryption with PKCS1Padding (legacy format)
    private final Cipher CIPHER_DECRYPT_PKCS1 = getCipherDecryptPKCS1();

    /**
     * Gets the timestamp for July 1st, 2026 00:00:00 UTC.
     * After this date, legacy PKCS1 cipher support will no longer be available.
     */
    private static long getLegacyDeprecationDate() {
        Calendar cal = Calendar.getInstance();
        cal.set(2026, Calendar.JULY, 1, 0, 0, 0);
        cal.set(Calendar.MILLISECOND, 0);
        return cal.getTimeInMillis();
    }

    /**
     * Checks if legacy PKCS1 cipher support has been deprecated.
     * @return true if current date is on or after July 1st, 2026
     */
    private static boolean isLegacyCipherDeprecated() {
        return System.currentTimeMillis() >= LEGACY_CIPHER_DEPRECATION_DATE_MILLIS;
    }


    abstract AlgorithmParameterSpec getInitParams(Context ctx, String alias, Integer userAuthenticationValidityDuration) throws Exception;

    boolean encryptionKeysAvailable(String alias) {
        return isEntryAvailable(alias);
    }

    String getRSAKey() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return KeyProperties.KEY_ALGORITHM_RSA;
        }
        return "RSA";
    }

    private Cipher getCipherEncrypt() {
        try {
            // Use OAEP padding with SHA-256 for secure encryption (Veracode compliant)
            return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        } catch (Exception e) {
            return null;
        }
    }

    private Cipher getCipherDecryptOAEP() {
        try {
            // Use OAEP padding for decryption (new format)
            return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        } catch (Exception e) {
            return null;
        }
    }

    private Cipher getCipherDecryptPKCS1() {
        try {
            // Use PKCS1Padding for decryption (legacy format for backward compatibility)
            return Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] runCipher(int cipherMode, String alias, byte[] buf) throws Exception {
        if (cipherMode == Cipher.ENCRYPT_MODE) {
            Key key = loadKey(cipherMode, alias);
            assert CIPHER_ENCRYPT != null;
            synchronized (CIPHER_ENCRYPT) {
                CIPHER_ENCRYPT.init(cipherMode, key);
                return CIPHER_ENCRYPT.doFinal(buf);
            }
        } else {
            // For decryption, try OAEP first (new format), then fallback to PKCS1 (legacy)
            Key key = loadKey(cipherMode, alias);
            try {
                assert CIPHER_DECRYPT_OAEP != null;
                synchronized (CIPHER_DECRYPT_OAEP) {
                    CIPHER_DECRYPT_OAEP.init(cipherMode, key);
                    return CIPHER_DECRYPT_OAEP.doFinal(buf);
                }
            } catch (Exception oaepException) {
                // Check if legacy PKCS1 support has been deprecated
                if (isLegacyCipherDeprecated()) {
                    throw new Exception(
                        "Legacy PKCS1 cipher support was deprecated on July 1st, 2026. " +
                        "Please update all encrypted data to use OAEP padding. " +
                        "Original error: " + oaepException.getMessage(),
                        oaepException);
                }
                
                // OAEP failed and legacy support still active, try legacy PKCS1Padding
                try {
                    assert CIPHER_DECRYPT_PKCS1 != null;
                    synchronized (CIPHER_DECRYPT_PKCS1) {
                        CIPHER_DECRYPT_PKCS1.init(cipherMode, key);
                        return CIPHER_DECRYPT_PKCS1.doFinal(buf);
                    }
                } catch (Exception pkcs1Exception) {
                    // Both failed, throw the original OAEP exception
                    throw oaepException;
                }
            }
        }
    }

    public void createKeyPair(Context ctx, String alias, Integer userAuthenticationValidityDuration) throws Exception {
        AlgorithmParameterSpec spec = getInitParams(ctx, alias, userAuthenticationValidityDuration);
        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(getRSAKey(), KEYSTORE_PROVIDER);
        kpGenerator.initialize(spec);
        kpGenerator.generateKeyPair();
    }

    public byte[] encrypt(byte[] buf, String alias) throws Exception {
        return runCipher(Cipher.ENCRYPT_MODE, alias, buf);
    }


    public byte[] decrypt(byte[] buf, String alias) throws Exception {
        return runCipher(Cipher.DECRYPT_MODE, alias, buf);
    }

    protected abstract boolean isEntryAvailable(String alias);

    Key loadKey(int cipherMode, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null, null);

        if (!keyStore.containsAlias(alias)) {
            throw new Exception("KeyStore doesn't contain alias: " + alias);
        }

        Key key;
        switch (cipherMode) {
            case Cipher.ENCRYPT_MODE:
                key = keyStore.getCertificate(alias).getPublicKey();
                if (key == null) {
                    throw new Exception("Failed to load the public key for " + alias);
                }
                break;
            case Cipher.DECRYPT_MODE:
                key = keyStore.getKey(alias, null);
                if (key == null) {
                    throw new Exception("Failed to load the private key for " + alias);
                }
                break;
            default:
                throw new Exception("Invalid cipher mode parameter");
        }
        return key;
    }

    boolean userAuthenticationRequired(String alias) {
        try {
            // Do a quick encrypt/decrypt test
            byte[] encrypted = encrypt(alias.getBytes(), alias);
            decrypt(encrypted, alias);
            return false;
        } catch (InvalidKeyException noAuthEx) {
            return true;
        } catch (Exception e) {
            // Other
            return false;
        }
    }
}

