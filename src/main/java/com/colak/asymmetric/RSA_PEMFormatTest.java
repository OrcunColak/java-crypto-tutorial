package com.colak.asymmetric;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


// See https://gaitatzis.medium.com/creating-compatible-asymmetric-keys-in-java-and-javascript-in-the-browser-98650fd9facc
// X509EncodedKeySpec can convert PublicKey to byte[]
// KeyFactory + X509EncodedKeySpec can convert byte[] to PublicKey

// PKCS8EncodedKeySpec can convert PrivateKey to byte[]
// KeyFactory + PKCS8EncodedKeySpec can convert byte[] to PrivateKey
class RSA_PEMFormatTest {

    public static void main() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(4096);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Test public key
        String publicKeyString = exportPublicKey(publicKey);
        PublicKey publicKeyLoaded = loadPublicKey(publicKeyString);

        if (publicKey.equals(publicKeyLoaded)) {
            System.out.println("Public keys are equal");
        }

        String privateKeyString = exportPrivate(privateKey);
        PrivateKey privateKeyLoaded = loadPrivateKey(privateKeyString);

        if (privateKey.equals(privateKeyLoaded)) {
            System.out.println("Private keys are equal");
        }
    }

    private static String exportPublicKey(PublicKey publicKey) {
        // get public key as a byte array
        byte[] publicKeyBytes = publicKey.getEncoded();
        // create an encoder
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        // Base64-encode the public key
        String base64PublicKey = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(publicKeySpec.getEncoded());

        return "-----BEGIN PUBLIC KEY-----\n" +
               base64PublicKey +
               "\n-----END PUBLIC KEY-----";
    }

    private static String exportPrivate(PrivateKey privateKey) {
        // export the private key to a byte array
        byte[] privateKeyBytes = privateKey.getEncoded();
        // create the key spec from the private key
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        // base64-encode the key
        String base64PrivateKey = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(privateKeySpec.getEncoded());

        return "-----BEGIN PRIVATE KEY-----\n" +
               base64PrivateKey +
               "\n-----END PRIVATE KEY-----";
    }

    private static PublicKey loadPublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyPem = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPem);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    private static PrivateKey loadPrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }
}
