package de.trustable.ca3s.challenge;

import de.trustable.ca3s.challenge.exception.ChallengeDNSException;
import de.trustable.ca3s.challenge.exception.ChallengeDNSIdentifierException;
import de.trustable.ca3s.challenge.test.TestDNSServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class ChallengeValidatorDNSTest {

    static Logger LOG = LoggerFactory.getLogger(ChallengeValidatorDNSTest.class);

    String resolverHost = "localhost";

    static int dnsPort;
    static TestDNSServer dnsServer;

    public final static String txtRecord1 = "abcdef1234567890";
    public final static String txtRecord2 = "0101010101010101";
    public final static String txtRecord3 = "_-_-_-_-_-_-_-_-";

    @BeforeAll
    static void setup() throws IOException {
        ServerSocket serverSocket = new ServerSocket(0);
        dnsPort = serverSocket.getLocalPort();
        LOG.info("dnsPort: {}", dnsPort);

        dnsServer = new TestDNSServer(dnsPort);
        dnsServer.start();
    }

    @Test
    public void testRetrieveChallengeDNSHappyPath() throws ChallengeDNSException, ChallengeDNSIdentifierException {

        ChallengeValidator challengeValidator = new ChallengeValidator(resolverHost,
                dnsPort,
                500,
                null,
                0,
                null);

        Collection<String> values = challengeValidator.retrieveChallengeDNS("FooBArBaz1234");

        assertEquals(3, values.size());
        assertTrue(values.contains(txtRecord1));
    }

    @Test
    public void testRetrieveChallengeNoDNSEntry() throws ChallengeDNSException, ChallengeDNSIdentifierException {

        ChallengeValidator challengeValidator = new ChallengeValidator(resolverHost,
                dnsPort,
                500,
                null,
                0,
                null);

        Collection<String> values = challengeValidator.retrieveChallengeDNS("Unknown.Entry");

        assertEquals(0, values.size());
    }

    @Test
    public void testRetrieveChallengeDNSNoResolver() throws IOException {

        ServerSocket serverSocket = new ServerSocket(0);

        ChallengeValidator challengeValidator = new ChallengeValidator(resolverHost,
                serverSocket.getLocalPort(),
                500,
                null, 0,
                null);

        try {
            Collection<String> values = challengeValidator.retrieveChallengeDNS("Unknown.Entry");
        } catch (ChallengeDNSException | ChallengeDNSIdentifierException ex){
            assertTrue( ex.getMessage().startsWith("Problem accessing DNS resolver:"));
        }
    }

}