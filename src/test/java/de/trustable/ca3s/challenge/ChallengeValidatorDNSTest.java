package de.trustable.ca3s.challenge;

import de.trustable.ca3s.challenge.exception.ChallengeDNSException;
import de.trustable.ca3s.challenge.exception.ChallengeDNSIdentifierException;
import de.trustable.ca3s.challenge.test.TestDNSServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Name;
import org.xbill.DNS.TXTRecord;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Collection;
import java.util.List;

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

    public final static String txtRecord4 = "persist1234567890";

    public static final String SPEC_SAMPLE_RECORD_MOD ="Authority.example;    foo=bar;;;" +
            " accounturi=https://ca.example/acct/123;" +
            " accounturi=https://ca.example/acct/124;" +
            " policy=wildcard; \n\n" +
            "     persistUntil=1721952000";

    public static final String SPEC_ALL_QUOTE_RECORD ="\"authority.example;\"" +
            " \"accounturi=https://ca.example/acct/123;\"" +
            " \"policy=wildcard;\"" +
            " \"persistUntil=1721952000\"";

    public static final String SPEC_SINGLE_QUOTE_RECORD ="\"authority.example;" +
            " accounturi=https://ca.example/acct/123;" +
            " policy=wildcard;" +
            " persistUntil=1721952000\"";


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


    @Test
    public void testRetrieveChallengeDNSPersistHappyPath() throws ChallengeDNSException, ChallengeDNSIdentifierException {

        ChallengeValidator challengeValidator = new ChallengeValidator(resolverHost,
                dnsPort,
                500,
                null,
                0,
                null);

        Collection<String> values = challengeValidator.retrieveChallengeDNSPersist("FooBArBaz1234");

        assertEquals(1, values.size());
        assertTrue(values.contains(txtRecord4));
    }

    @Test
    public void testRetrieveChallengeNoDNSPersistEntry() throws ChallengeDNSException, ChallengeDNSIdentifierException {

        ChallengeValidator challengeValidator = new ChallengeValidator(resolverHost,
                dnsPort,
                500,
                null,
                0,
                null);

        Collection<String> values = challengeValidator.retrieveChallengeDNSPersist("Unknown.Entry");

        assertEquals(0, values.size());
    }


    @Test
    public void testExtractTokenFrom() {

        ChallengeValidator challengeValidator = new ChallengeValidator(resolverHost,
                dnsPort,
                500,
                null,
                0,
                null);

        List<String> tokenList = challengeValidator.extractTokenFrom(getTxtRecords(SPEC_SAMPLE_RECORD_MOD));
        assertEquals(1, tokenList.size());

        tokenList = challengeValidator.extractTokenFrom(getTxtRecords(SPEC_SINGLE_QUOTE_RECORD));
        assertEquals(1, tokenList.size());
        tokenList = challengeValidator.extractTokenFrom(getTxtRecords(SPEC_ALL_QUOTE_RECORD));
        assertEquals(1, tokenList.size());



    }

    private static TXTRecord[] getTxtRecords(String recordAsString) {
        TXTRecord[] lookupResult = new TXTRecord[1];
        lookupResult[0] = new TXTRecord(Name.fromConstantString("_acme-challenge.FooBArBaz1234."), 1, 1,
                recordAsString);
        return lookupResult;
    }

}