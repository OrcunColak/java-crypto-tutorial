package com.colak.asymmetric;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

// From <a href="https://medium.com/@sharadblog/encryption-and-decryption-in-java-60948b8a3613">...</a>
@Slf4j
class RSACryptoTest {

    // Encrypt and decrypt using the RSA algorithm with PKCS1Padding.
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    public static void main() throws Exception {
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn4pp9Iqmz/WZtd/nQJIocOsvMc0l4C+H7ex9bfyYN9pLjaXohgZub6meVawI8KNWVrRfx9psSF2V22DM88IBWO8Fw2BSxXSKcCGffuGhycY48p2lpKdBKNVp0EFZNIf2wZjS9sF9Jz0WfepcDTCoxkxl1p24vNHqIReEGJyVeo6i9bLjdnNgry7u7vMY+ogLeLhytdnO2lJP5aRRr8DzPvBLwf67oC3VcgE3KZ6EMYzaAcqR36Aytci/YVt9RnQEQ65Uo8GwzGYo2kAnAEmMHBEKX1iJwmMUuGFAMif9LdykOvhlKC808rkJgThLEHHcCtJLNWKWrJIUYsbtrYiFuQIDAQAB";
        String privateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCfimn0iqbP9Zm13+dAkihw6y8xzSXgL4ft7H1t/Jg32kuNpeiGBm5vqZ5VrAjwo1ZWtF/H2mxIXZXbYMzzwgFY7wXDYFLFdIpwIZ9+4aHJxjjynaWkp0Eo1WnQQVk0h/bBmNL2wX0nPRZ96lwNMKjGTGXWnbi80eohF4QYnJV6jqL1suN2c2CvLu7u8xj6iAt4uHK12c7aUk/lpFGvwPM+8EvB/rugLdVyATcpnoQxjNoBypHfoDK1yL9hW31GdARDrlSjwbDMZijaQCcASYwcEQpfWInCYxS4YUAyJ/0t3KQ6+GUoLzTyuQmBOEsQcdwK0ks1YpaskhRixu2tiIW5AgMBAAECggEAEzobpdiAh7HPdKnyFTKSxB+xKt0l55GNiKtxEaxuQyuVjRHFvEKR1Ew1Tu7c5En9sZUAXAtjSbSu8ZGGHF8GSYuuKUsg/oyafdlXfvOTS3K4/JLqL7Xmdj+DW+acPmafuC+CRocFXbwQy1ukp1mfZXKMmA5JrBvXjbsR9ONeEmG7JOUAA5bzLE+wI9AmXFMEXM+AjRN2jvfjVWW6RrlSMKrD4it+OL/2AAsdHyTgF1kTjZJD3/HTc2IZ7Vglck7vFGmizOJI1pFE8N3Qfw3Qt28AiTorCe+7XoGzohYkZnMB6VSFAM8rwNgfpAqL8WePJE0zdvFKQyNiDgQKzCgPTwKBgQC+pRZbKoASdZ/oVOdoKCpyEOkOES0o/tA+OCCXZRzKNJsyHkrmg/K/NqbuXACUTkHOD6yRGpi+C8sWSEwqU6HygAPYK3axz+lG6ux+2ImIop0hbx6+G6gDzBDIzliecNskTZRLSZbRj4MA0UZ+dT1he6gW4lOsJVcO0/o2+I1iWwKBgQDWO6LGWQDH2vu3stvhxV9EkNUoAI7nrGXrdEAWetzUwztBP+9k49k9yS5ZY9w0bukLhme/sG4IvVLCsd3aXUc3rmQS4qAF9FJfiN4jgA8Qgy4l8TaP1JoaeMAXPUogtV1o/Wey59quRVuQEyBZgV9BpxRjMv50ZySNtGqut1oMewKBgDzyG8aDPLQqBDfKxLuIc6FJhKepmA1OAJaTbN/ZRC3kSWTpSDqPHhBA0XbL1KeUqPbODfXJUeEXdhImhKrXV6Nlh1UY9/X6KHIyce5PHRCgI6lnk6Vkw/6KwybeyHfGTlg5sNmsqdlOjqu5O1b79eZvGJpQOj2DJmSoIYpnRROXAoGAYYb2nEtqYpFbZI5lMUvUCffRQgu3Atrl7yGWB2XZYHacZCECD7D2df0/P2yJk8kmCJwgYRCllw7xPTcR41XxlPSsFDjdVriaQ2mgjxK+SOsfOCCukR3dJc3wzOOW+nr2UlSCP9zzHcDvZRB/+p89yTqRunM9iapm5qfKpU1NDj8CgYA405QJoHxFHrpMfqCZjtFHVs1ja3+VyqdXJi7DEMnuoJfa5CMk+7AxaS7ELzU9dxoSxDUcE3UzslX5MOa1FRUNeUaIjDJ4pKZ2j2hIKWwIXHvg7DyglXRTPMDl3+tvroOoPFlzD7tu7fDV+eU3UlqwSBdN4QjBBOQMs1sQ8JFIGQ==";

        // Original message
        String originalMessage = "Hello, this is a secret message!";

        log.info("Original message: {}", originalMessage);
        // Encrypt using the public key
        String encryptedMessage = encrypt(originalMessage, publicKey);

        log.info("Encrypted message: {}", encryptedMessage);

        // Decrypt using the private key
        String decryptedMessage = decrypt(encryptedMessage, privateKey);

        log.info("Decrypted message: {}", decryptedMessage);
    }


    private static String encrypt(String message, String publicKeyString) throws GeneralSecurityException {
        // Public key is decoded from a Base64 string and used to initialize the encryption cipher
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString.getBytes());

        // Generates an RSA public key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // Encrypt
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static String decrypt(String encryptedMessage, String privateKeyString) throws GeneralSecurityException {
        // Private key is decoded from a Base64 string and used to initialize the encryption cipher
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString.getBytes());

        // Generates an RSA private key
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Decrypt
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decoded = Base64.getDecoder().decode(encryptedMessage);
        byte[] bytes = cipher.doFinal(decoded);
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
