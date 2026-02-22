package de.trustable.ca3s.challenge;


import de.trustable.ca3s.challenge.exception.ChallengeDNSException;
import de.trustable.ca3s.challenge.exception.ChallengeDNSIdentifierException;
import de.trustable.ca3s.challenge.exception.ChallengeUnknownHostException;
import de.trustable.ca3s.challenge.exception.ChallengeValidationFailedException;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;

import javax.net.ssl.*;
import java.io.*;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static org.xbill.DNS.Name.*;
import static org.xbill.DNS.Type.TXT;
import static org.xbill.DNS.Type.string;


public class ChallengeValidator {

    transient Logger LOG = LoggerFactory.getLogger(ChallengeValidator.class);

    public static final String ACME_CHALLENGE_PREFIX_STRING = "_acme-challenge";
    public static final Name ACME_CHALLENGE_PREFIX = fromConstantString(ACME_CHALLENGE_PREFIX_STRING);

    /**
     * OID of the {@code acmeValidation} extension.
     */
    public static final String ACME_VALIDATION_OID = "1.3.6.1.5.5.7.1.31";
    public static final String ACME_TLS_1_PROTOCOL = "acme-tls/1";

    final private int[] ports;
    final private int maxRedirects;
    final private int[] httpsPorts;
    final private long timeoutMilliSec;

    private boolean dnsActive;
    private SimpleResolver dnsResolver;

    public ChallengeValidator(final String resolverHost,
                              int resolverPort,
                              long timeoutMilliSec,
                              int[] ports,
                              int maxRedirects,
                              int[] httpsPorts) {

        if(resolverHost == null || resolverHost.isEmpty()){
            this.dnsActive = false;
            this.dnsResolver = null;
            LOG.info("DNS resolver not configured");
        }else{
            try {
                this.dnsResolver = new SimpleResolver(resolverHost);
                this.dnsResolver.setPort(resolverPort);
                LOG.info("Applying default DNS resolver {}", this.dnsResolver.getAddress());
                this.dnsActive = true;
            } catch (UnknownHostException e) {
                this.dnsActive = false;
                LOG.info("Initialization of DNS resolver at '" + resolverHost + "':"+resolverPort+" failed!");
            }
        }

        this.timeoutMilliSec = timeoutMilliSec;
        LOG.info("timeoutMilliSec '{}'", timeoutMilliSec );

        this.maxRedirects = maxRedirects;
        LOG.info("maxRedirects '{}'", maxRedirects );

        if( ports == null || ports.length == 0){
            this.ports = new int[]{80, 5544, 8800};
            LOG.info("Using default HTTP-01 challenge ports  '{}'", delimitedArray(this.ports));
        }else {
            this.ports = ports;
            LOG.info("Using provided HTTP-01 challenge ports  '{}'", delimitedArray(this.ports) );
        }

        if( httpsPorts == null || httpsPorts.length == 0){
            this.httpsPorts = new int[]{443, 8443};
            LOG.info("Using default ALPN ports  '{}'", delimitedArray(this.httpsPorts) );
        }else {
            this.httpsPorts = httpsPorts;
            LOG.info("Using provided ALPN ports  '{}'", delimitedArray(this.httpsPorts) );
        }
    }

    private String delimitedArray(final int[] ports){
        return Arrays.stream(ports).mapToObj(String::valueOf).collect(Collectors.joining(", "));
    }

    public Collection<String> retrieveChallengeDNS(final String identifierValue) throws ChallengeDNSIdentifierException, ChallengeDNSException {

        if(!this.dnsActive){
            throw new ChallengeDNSException("DNS challenge not configured / not supported");
        }

        final Name nameToLookup;
        try {
            final Name nameOfIdentifier = fromString(identifierValue, root);
            LOG.info("DNS TXT lookup for identifier '" + identifierValue + "'");
            nameToLookup = concatenate(ACME_CHALLENGE_PREFIX, nameOfIdentifier);

        } catch (TextParseException | NameTooLongException e) {
            String msg = "problem while DNS lookup of identifier '" + identifierValue + "'";
            throw new ChallengeDNSIdentifierException(msg);
        }

        final Lookup lookupOperation = new Lookup(nameToLookup, TXT);
        lookupOperation.setResolver(dnsResolver);
        lookupOperation.setCache(null);
        LOG.info("DNS lookup: {} records of '{}' (via resolver '{}')", string(TXT), nameToLookup, this.dnsResolver.getAddress());

        final Instant startedAt = Instant.now();
        final org.xbill.DNS.Record[] lookupResult = lookupOperation.run();
        LOG.info("lookupOperation result {}, error: {}",lookupOperation.getResult(),lookupOperation.getErrorString());
        switch (lookupOperation.getResult()){
            case Lookup.SUCCESSFUL:
                // as expected ...
                break;

            case Lookup.TYPE_NOT_FOUND:
                return (Collection<String>)Collections.EMPTY_LIST;

            case Lookup.HOST_NOT_FOUND:
                throw new ChallengeDNSException("Problem accessing DNS resolver: HOST_NOT_FOUND");

            case Lookup.TRY_AGAIN:
                throw new ChallengeDNSException("Problem accessing DNS resolver: TRY_AGAIN");

            case Lookup.UNRECOVERABLE:
                throw new ChallengeDNSException("Problem accessing DNS resolver: UNRECOVERABLE");

            default:
                String msg = "Unexpected DNS lookup result: " + lookupOperation.getResult();
                LOG.warn(msg);
                throw new ChallengeDNSException("Problem accessing DNS resolver: UNRECOVERABLE");
        }

        final Duration lookupDuration = Duration.between(startedAt, Instant.now());
        LOG.info("DNS lookup yields: {} (took {})", Arrays.toString(lookupResult), lookupDuration);

        return extractTokenFrom(lookupResult);

    }


    public String retrieveChallengeHttp(String host, final String token) throws ChallengeUnknownHostException, ChallengeValidationFailedException {

        String fileNamePath = "/.well-known/acme-challenge/" + token;

        for( int port: ports) {

            try (CloseableHttpClient instance = HttpClientBuilder.create()
                    .setRedirectStrategy(new LaxRedirectStrategy())
                    .build()){

                URL url = new URL("http", host, port, fileNamePath);
                LOG.debug("Opening connection to  : " + url);

                RequestConfig requestConfig = RequestConfig.custom()
                        .setConnectionRequestTimeout((int)timeoutMilliSec)
                        .setConnectTimeout((int)timeoutMilliSec)
                        .setSocketTimeout((int)timeoutMilliSec)
                        .build();

                String currentUrl = url.toString();
                int redirectCounter = this.maxRedirects;
                do {
                    HttpGet request = new HttpGet(currentUrl);
                    request.addHeader(HttpHeaders.USER_AGENT, "CA3S_ACME");
                    request.setConfig(requestConfig);

                     HttpResponse response = instance.execute(request);
                     int responseCode = response.getStatusLine().getStatusCode();

                     LOG.debug("\nSending 'GET' request to URL : " + currentUrl);
                     LOG.debug("Response Code : " + responseCode);

                    if( (responseCode >= 300 && responseCode < 400) && (response.getHeaders(HttpHeaders.LOCATION).length > 0) ){

                        redirectCounter--;
                        if( redirectCounter == 0){
                            LOG.info("Response code '{}', but max number of redirects reached, failing", responseCode);
                            continue;
                        }

                        String redirectUrl = response.getFirstHeader(HttpHeaders.LOCATION).getValue();
                        if( !redirectUrl.isEmpty()){
                            currentUrl = redirectUrl;
                            LOG.info("Location header present, forwarding to {}. Redirects left {}", redirectUrl, redirectCounter);
                            continue;
                        }else{
                            LOG.info("Response code '{}', but no valid location header, failing", responseCode);
                        }
                    }

                    if (responseCode != 200) {
                        String msg = "read challenge responded with unexpected code : " + responseCode;
                        LOG.info(msg);
                        continue;
                    }

                    return readChallengeResponse(response.getEntity().getContent());

                }while(redirectCounter > 0);

            } catch(UnknownHostException uhe) {
                if( LOG.isDebugEnabled()) {
                    LOG.debug("exception occurred reading challenge response", uhe);
                }
                String msg = "unable to resolve hostname: '" + host + ":"+port+ "' checking HTTP-01 challenge.";
                LOG.info(msg);
                throw new ChallengeUnknownHostException(msg);
            } catch(SocketTimeoutException | ConnectTimeoutException ste) {
                if( LOG.isDebugEnabled()) {
                    LOG.debug("exception occurred reading challenge response", ste);
                }
                String msg = "timeout connecting to '"+host+":"+port+ "'  checking HTTP-01 challenge!";
                LOG.info(msg);
                // go on trying other ports
            } catch(IOException ioe) {
                if( LOG.isDebugEnabled()) {
                    LOG.debug("exception occurred reading challenge response", ioe);
                }
                String msg = "problem reading HTTP-01 challenge response on '"+host+":"+port+"' : " + ioe.getMessage();
                LOG.info(msg);
                // go on trying other ports
            }
        }

        throw new ChallengeValidationFailedException();
    }

    private String readChallengeResponse(InputStream is) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(is));
        String inputLine;
        StringBuilder response = new StringBuilder();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
            if (response.length() > 1000) {
                LOG.debug("limiting read of challenge response to 1000 characters.");
                break;
            }
        }
        in.close();

        String actualContent = response.toString().trim();

        if( actualContent.length() > 100){
            LOG.debug("read challenge response (truncated): " + actualContent.substring(0,100) + " ...");
        }else {
            LOG.debug("read challenge response: " + actualContent);
        }

        return actualContent;
    }


    public String retrieveChallengeALPN(final String host) throws GeneralSecurityException, ChallengeUnknownHostException, ChallengeValidationFailedException {

        // this is rare case where a trustAll-Manager makes sense as the details of the certificate get checked later on
        // please think twice before using the trustAll-Manager in a productive context !!
        TrustManager[] trustAllCerts = { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        } };

        for( int port: httpsPorts) {

            try {
                return validateALPNChallenge( host, trustAllCerts, port);

            } catch(UnknownHostException uhe) {
                if( LOG.isDebugEnabled()) {
                    LOG.debug("exception occurred reading challenge response", uhe);
                }
                String msg = "unable to resolve hostname: '" + host + "'";
                LOG.info(msg);
                throw new ChallengeUnknownHostException(msg);
            } catch(IOException ioe) {
                if( LOG.isDebugEnabled()) {
                    LOG.debug("exception occurred reading challenge response", ioe);
                }
                String msg = "problem reading alpn certificate on "+host+":"+port+" : " + ioe.getMessage();
                LOG.info(msg);
            } catch (CertificateException ce) {
                if( LOG.isDebugEnabled()) {
                    LOG.debug("exception occurred reading alpn challenge response certificate", ce);
                }
                String msg = "problem reading alpn challenge response in certificate provided by "+host+":"+port+" : " + ce.getMessage();
                LOG.info(msg);
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                throw new GeneralSecurityException(e);
            }
        }

        throw new ChallengeValidationFailedException();
    }

    private String validateALPNChallenge(String host, TrustManager[] trustAllCerts, int port) throws IOException, CertificateException, NoSuchAlgorithmException, KeyManagementException {
        LOG.debug("Opening ALPN connection to {}:{} ", host, port);

        Certificate[] serverCerts;
        SSLSocket sslSocket = null;
        try {
            // Code for creating a client side SSLSocket
            SSLContext sslContext = SSLContext.getInstance("TLS");

            sslContext.init(null, trustAllCerts, new SecureRandom());
            SSLSocketFactory sslsf = sslContext.getSocketFactory();

            sslSocket = (SSLSocket) sslsf.createSocket(host, port);

            // Get an SSLParameters object from the SSLSocket
            SSLParameters sslp = sslSocket.getSSLParameters();

            SNIHostName serverName = new SNIHostName(host);
            sslp.setServerNames(Collections.singletonList(serverName));

            // Populate SSLParameters with the ALPN values
            // On the client side the order doesn't matter as
            // when connecting to a JDK server, the server's list takes priority
            String[] clientAPs = {ACME_TLS_1_PROTOCOL};
            sslp.setApplicationProtocols(clientAPs);


            // Populate the SSLSocket object with the SSLParameters object
            // containing the ALPN values
            sslSocket.setSSLParameters(sslp);

            sslSocket.startHandshake();

            // After the handshake, get the application protocol that has been negotiated
            String ap = sslSocket.getApplicationProtocol();
            LOG.debug("Application Protocol server side: \"" + ap + "\"");

            serverCerts = sslSocket.getSession().getPeerCertificates();

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            LOG.warn("algorithm initialization problem ",e);
            throw e;
        } finally {
            if( sslSocket != null) {
                sslSocket.close();
            }
        }

        if(serverCerts.length == 0){
            String msg ="no certificate available after connection with " + host + ":" + port;
            LOG.info(msg);
            throw new CertificateException(msg);
        }else if(serverCerts.length > 1){
            String msg = "more than one (#"+serverCerts.length+") certificate returned "+ host + ":"+ port+", expecting a single selfsigned certificate";
            LOG.info(msg);
            throw new CertificateException(msg);
        }

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(serverCerts[0].getEncoded());
        X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);

        // check certificate details
        validateALPNCertificate(host, port, cert);

        byte[] acmeValidationExtBytes = cert.getExtensionValue(ACME_VALIDATION_OID);
        ASN1OctetString octetString = (ASN1OctetString) ASN1OctetString.fromByteArray(acmeValidationExtBytes);
        ASN1OctetString rfc8737OctetString = (ASN1OctetString) ASN1OctetString.fromByteArray(octetString.getOctets());
        String actualContent = Base64.getEncoder().encodeToString(rfc8737OctetString.getOctets());

        if( rfc8737OctetString.getOctets().length > 32){
            String msg = ("actualContent has unexpected length of rfc8737OctetString : "+ rfc8737OctetString.getOctets().length);
/*
            byte[] challenge = new byte[32];
            System.arraycopy(rfc8737OctetString.getOctets(), rfc8737OctetString.getOctets().length - 32, challenge, 0, 32);
            actualContent = Base64.getEncoder().encodeToString(challenge);
*/
            LOG.info(msg);
            throw new CertificateException(msg);
        }

        LOG.debug("read challenge response: " + actualContent);

        return actualContent;

    }

    private void validateALPNCertificate( String host, int port, X509Certificate cert) throws CertificateException {

        if( LOG.isDebugEnabled()){
            try {
                LOG.debug("alpn certificate : {}", Base64.getEncoder().encodeToString(cert.getEncoded()));
            } catch (CertificateEncodingException e) {
                String msg = "Encoding problem parsing ALPN certificate";
                LOG.info(msg);
                throw e;
            }
        }

        // Check SAN entry
        if( cert.getSubjectAlternativeNames() == null ||
            cert.getSubjectAlternativeNames().isEmpty()){
            String msg = "no SAN entry available in certificate provided by " + host + ":" + port;
            LOG.info(msg);
            throw new CertificateException(msg);
        } else if( cert.getSubjectAlternativeNames().size() > 1){
            String msg = "more than one SAN entry (#"+cert.getSubjectAlternativeNames().size()+") included in certificate provided by " + host + ":" + port;
            LOG.info(msg);
            throw new CertificateException(msg);
        }

        Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
        if (altNames != null) {
            for (List<?> altName : altNames) {
                int altNameType = (Integer) altName.get(0);

                if (GeneralName.dNSName == altNameType){
                    String sanValue = "";
                    if (altName.get(1) instanceof String) {
                        sanValue = ((String) altName.get(1)).toLowerCase();
                    } else if (altName.get(1) instanceof byte[]) {
                        sanValue = new String((byte[]) (altName.get(1))).toLowerCase();
                    }

                    if( host.equalsIgnoreCase(sanValue)){
                        LOG.debug("SAN entry '{}' machtes expected host '{}'", sanValue, host);
                    }else{
                        String msg = "SAN entry value ("+ sanValue+") in alpn certificate provided by '" + host + ":" + port + "', does not match expected host '" + host + "'";
                        LOG.info(msg);
                        throw new CertificateException(msg);
                    }
                }else{
                    String msg = "unexpected SAN entry type ("+ altNameType+") in alpn certificate provided by '" + host + ":" + port + "', 'DNS' (2) expected.";
                    LOG.info(msg);
                    throw new CertificateException(msg);
                }
            }
        }

        // Check ACME extension
        if( cert.getCriticalExtensionOIDs().contains(ACME_VALIDATION_OID) ){
            LOG.debug("ACME validation oid is present and marked as critical!");
        }else{
            String msg = "ACME validation oid is NOT present and NOT marked as critical in certificate provided by '" + host + ":" + port + "'";
            LOG.info(msg);
            throw new CertificateException(msg);
        }
    }

    /**
     * @param lookupResult Optional
     * @return Never <code>null</code>
     */
    private List<String> extractTokenFrom(final Record[] lookupResult) {

        List<String> tokenList = new ArrayList<>();
        if( lookupResult != null) {
            for (Record record : lookupResult) {
                LOG.debug("Found DNS entry solving '{}'", record);
                tokenList.addAll(((TXTRecord) record).getStrings());
            }
        }
        return tokenList;
    }


}
