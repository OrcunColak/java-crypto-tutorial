package com.colak.signature;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

// ML-DSA is based on Dilithium
@Slf4j
@UtilityClass
public class ML_DSA_DigitalSignatureTest {

    public static void main() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA");
        // keysize not supported
        // keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String input = "password";

        byte[] data = input.getBytes(StandardCharsets.UTF_8);
        byte[] digitalSignature = signData(data, privateKey);

        boolean isVerified = verifyData(data, digitalSignature, publicKey);
        log.info("Signature verification result: {}", isVerified);
    }

    private static byte[] signData(byte[] dataBytes, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("ML-DSA");
        signature.initSign(privateKey);

        signature.initSign(privateKey);
        signature.update(dataBytes);
        return signature.sign();
    }

    private static boolean verifyData(byte[] dataBytes, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("ML-DSA");
        signature.initVerify(publicKey);
        signature.update(dataBytes);
        return signature.verify(signatureBytes);
    }
}
