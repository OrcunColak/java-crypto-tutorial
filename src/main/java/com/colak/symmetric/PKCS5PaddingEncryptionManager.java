package com.colak.symmetric;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * See <a href="https://github.com/bmvermeer/java-encryption/blob/master/src/main/java/EncryptionServiceAESGCM.java">...</a>
 */
@Slf4j
class PKCS5PaddingEncryptionManager {

    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";


    public String encrypt(String message, SecretKey secretKey) throws GeneralSecurityException {
        // Generate a random IV (Initialization Vector)
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv); // Generate a random IV

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        byte[] encryptedData = cipher.doFinal(message.getBytes());

        // Combine IV and ciphertext for later decryption
        var encoder = Base64.getEncoder();
        var encrypt64 = encoder.encode(encryptedData);
        var iv64 = encoder.encode(iv);
        return new String(encrypt64) + "#" + new String(iv64);
    }

    public String decrypt(String encryptedMessage, SecretKey secretKey) throws GeneralSecurityException {
        // Extract IV from the combined data
        var split = encryptedMessage.split("#");
        var decoder = Base64.getDecoder();
        var cypherText = decoder.decode(split[0]);
        var iv = decoder.decode(split[1]);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedData = cipher.doFinal(cypherText);
        return new String(decryptedData);
    }
}
