package com.colak.symmetric;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

/**
 * See <a href="https://github.com/bmvermeer/java-encryption/blob/master/src/main/java/EncryptionServiceAESGCM.java">...</a>
 */
@Slf4j
@UtilityClass
class AESGCMTest {

    public static void main() throws GeneralSecurityException {
        testPKCS5PaddingEncryptionManager();
        testNoPaddingEncryptionManager();
    }

    private static void testNoPaddingEncryptionManager() throws GeneralSecurityException {
        // Original message
        String originalMessage = "Hello, this is a secret message!";

        String passphrase = "YourPassphraseHere";
        SecretKey secretKey = SecretKeyGenerator.generateAesKey(passphrase);

        NoPaddingEncryptionManager noPaddingEncryptionManager = new NoPaddingEncryptionManager();
        // Encrypt using the public key
        String encryptedMessage = noPaddingEncryptionManager.encrypt(originalMessage, secretKey);

        log.info("Encrypted message for No Padding: {}", encryptedMessage);

        // Decrypt using the private key
        String decryptedMessage = noPaddingEncryptionManager.decrypt(encryptedMessage, secretKey);

        log.info("Decrypted message for No Padding: {}", decryptedMessage);
    }

    private static void testPKCS5PaddingEncryptionManager() throws GeneralSecurityException {
        // Original message
        String originalMessage = "Hello, this is a secret message!";

        String passphrase = "YourPassphraseHere";
        SecretKey secretKey = SecretKeyGenerator.generateAesKey(passphrase);

        PKCS5PaddingEncryptionManager pkcs5PaddingEncryptionManager = new PKCS5PaddingEncryptionManager();
        // Encrypt using the public key
        String encryptedMessage = pkcs5PaddingEncryptionManager.encrypt(originalMessage, secretKey);

        log.info("Encrypted message for PKCS5: {}", encryptedMessage);

        // Decrypt using the private key
        String decryptedMessage = pkcs5PaddingEncryptionManager.decrypt(encryptedMessage, secretKey);

        log.info("Decrypted message for PKCS5: {}", decryptedMessage);
    }

}
