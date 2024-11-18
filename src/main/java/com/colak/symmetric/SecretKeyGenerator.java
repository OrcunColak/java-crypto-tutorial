package com.colak.symmetric;

import lombok.experimental.UtilityClass;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

@UtilityClass
class SecretKeyGenerator {

    public static SecretKey generateAesKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        // Using a 256-bit key for AES
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static SecretKey generateAesKey(String passphrase) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = getKeyBytesWithPBKDF2(passphrase);

        // Create a SecretKey from the encoded key
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] getKeyBytesWithPBKDF2(String passphrase) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Generate a salt (random bytes)
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);

        return getKeyBytesWithPBKDF2(passphrase, salt);
    }

    private static byte[] getKeyBytesWithPBKDF2(String passphrase, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Using a 256-bit key for AES
        int keyLength = 256;
        // Number of iterations, you can adjust this based on your security requirements
        int iterations = 10_000;

        // Use PBKDF2 with the given passphrase, salt, key length, and iterations
        KeySpec keySpec = new PBEKeySpec(passphrase.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return secretKeyFactory.generateSecret(keySpec).getEncoded();
    }
}
