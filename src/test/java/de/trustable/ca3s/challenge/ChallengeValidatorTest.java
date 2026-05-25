package de.trustable.ca3s.challenge;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Random;

import static de.trustable.ca3s.challenge.util.AcmeAlpnCertGenerator.createAlpnCerticate;
import static org.junit.jupiter.api.Assertions.*;

class ChallengeValidatorTest {

    public ChallengeValidator challengeValidator = new ChallengeValidator("resolverHost",
                              1234,
                              1234,
                              null,
                              1,
                              null);

    @Test
    public void testExtractValidationAttribute() throws CertificateException, IOException, NoSuchAlgorithmException, OperatorCreationException {

        String host = "host";
        int port = 1234;
        Certificate[] serverCerts = new Certificate[1];

        Random rand  = new Random();
        byte[] challengeBytes = new byte[32];
        rand.nextBytes(challengeBytes);
        serverCerts[0] = createAlpnCerticate(host, challengeBytes);

        String expectedContent = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);

        String encodedValue = challengeValidator.extractValidationAttribute(host, port, serverCerts);

        assertEquals(expectedContent, encodedValue);

    }

}