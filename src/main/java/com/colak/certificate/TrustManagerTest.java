package com.colak.certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

// This code demonstrates how to load an X.509 certificate from a byte array and set up a TrustManager that can be used for SSL/TLS connections.
// See https://nikhilsomansahu.medium.com/spring-boot-ssl-configuration-how-to-embed-certificate-content-in-application-yml-c860ee62f4e0
class TrustManagerTest {

    private static final byte[] CERT_MULTI_CN = """
            -----BEGIN CERTIFICATE-----
            MIIBwDCCAWOgAwIBAgIEPWQKdjAMBggqhkjOPQQDAgUAMFQxCzAJBgNVBAYTAkNa
            MRIwEAYDVQQDEwloYXplbGNhc3QxEjAQBgNVBAMTCUhhemVsY2FzdDENMAsGA1UE
            CxMEdGVzdDEOMAwGA1UEAxMFcm9sZTEwHhcNMTkwNTMxMTIyMjUxWhcNMzkwNTI2
            MTIyMjUxWjBUMQswCQYDVQQGEwJDWjESMBAGA1UEAxMJaGF6ZWxjYXN0MRIwEAYD
            VQQDEwlIYXplbGNhc3QxDTALBgNVBAsTBHRlc3QxDjAMBgNVBAMTBXJvbGUxMFkw
            EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/I/a7/D8vymPIOPbcVjB2Y4d6KqIRDCa
            Y7WC+YpFRnw/t8n24wXT9J/SNthJcZHw2HTtrIzu45qB1orSdR58J6MhMB8wHQYD
            VR0OBBYEFI5JYi0raYr3A6/zX3Vyc2uVS0/iMAwGCCqGSM49BAMCBQADSQAwRgIh
            AKAHXF4YNBsfXsj+LIeaQaCnXb77ljzHkSyBVhRmq6j1AiEAiHu+AkhEnelx6LGf
            irp3QV0GYW2w9/relFiywoDFkbM=
            -----END CERTIFICATE-----
            """.getBytes(StandardCharsets.UTF_8);

    public static void main() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(CERT_MULTI_CN);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(byteArrayInputStream);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        // This loads the KeyStore, initializing it to an empty state since no input stream or password is provided
        // (which is useful for adding certificates in-memory).
        keyStore.load(null);

        // The certificate (cert) is added to the KeyStore with the alias "cert".
        keyStore.setCertificateEntry("cert", cert);
        // The TrustManagerFactory is initialized with the KeyStore.
        // This tells the TrustManagerFactory to use the certificates in the KeyStore for trust management.
        trustManagerFactory.init(keyStore);

        // The TrustManagerFactory returns an array of TrustManager objects, which can be used to manage the trust relationship during SSL/TLS handshakes.
        // These TrustManager objects will use the certificate you added earlier to establish trusted connections.
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
    }
}
