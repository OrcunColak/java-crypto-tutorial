package com.colak.certificate;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;

// CertificateFactory can read certificates
@Slf4j
@UtilityClass
class CertificateTest {

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

    public static void main() throws CertificateException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(CERT_MULTI_CN);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(byteArrayInputStream);
        for (Certificate certificate : certificates) {
            log.info(certificate.toString());
        }
    }
}
