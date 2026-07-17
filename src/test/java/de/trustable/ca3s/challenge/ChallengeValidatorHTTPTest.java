package de.trustable.ca3s.challenge;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import de.trustable.ca3s.challenge.exception.ChallengeUnknownHostException;
import de.trustable.ca3s.challenge.exception.ChallengeValidationFailedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ChallengeValidatorHTTPTest {
    public static final String TOKEN_RESPONSE = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
    private WireMockServer wireMockServer;

    int port = 8080;

    @BeforeEach
    void setup() {
        wireMockServer = new WireMockServer(WireMockConfiguration.options().port(port));
        wireMockServer.start();
        WireMock.configureFor("localhost", port);
    }

    @AfterEach
    void teardown() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    @Test
    void testValidChallenge() throws ChallengeUnknownHostException, ChallengeValidationFailedException {

        final String token = "token";
        int[] ports = new int[]{port};

        ChallengeValidator challengeValidator = new ChallengeValidator(null,
                0,
                100L,
                ports,
                3,
                ports);


        stubFor(get(urlPathMatching("/.well-known/acme-challenge/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/octet-stream")
                        .withBody(TOKEN_RESPONSE)));

        String response = challengeValidator.retrieveChallengeHttp("localhost", token);
        assertEquals(TOKEN_RESPONSE, response);
    }
}
