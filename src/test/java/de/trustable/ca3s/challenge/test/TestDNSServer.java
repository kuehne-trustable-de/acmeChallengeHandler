package de.trustable.ca3s.challenge.test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

import static de.trustable.ca3s.challenge.ChallengeValidator.ACME_CHALLENGE_PREFIX;
import static de.trustable.ca3s.challenge.ChallengeValidatorDNSTest.txtRecord1;
import static de.trustable.ca3s.challenge.ChallengeValidatorDNSTest.txtRecord2;
import static de.trustable.ca3s.challenge.ChallengeValidatorDNSTest.txtRecord3;

import static org.xbill.DNS.Name.*;


public class TestDNSServer {
    private static final Logger logger = LoggerFactory.getLogger(TestDNSServer.class);

    private Thread thread = null;
    private volatile boolean running = false;
    private static final int UDP_SIZE = 512;
    private final int port;
    private int requestCount = 0;

    public TestDNSServer(int port) {
        this.port = port;
    }

    public void start() {
        running = true;
        thread = new Thread(() -> {
            try {
                serve();
            } catch (IOException ex) {
                stop();
                throw new RuntimeException(ex);
            }
        });
        thread.start();
    }

    public void stop() {
        running = false;
        thread.interrupt();
        thread = null;
    }

    public int getRequestCount() {
        return requestCount;
    }

    private void serve() throws IOException {
        DatagramSocket socket = new DatagramSocket(port);
        while (running) {
            process(socket);
        }
    }

    private void process(DatagramSocket socket) throws IOException {
        byte[] in = new byte[UDP_SIZE];

        // Read the request
        DatagramPacket indp = new DatagramPacket(in, UDP_SIZE);
        socket.receive(indp);
        ++requestCount;
        logger.info(String.format("processing... %d", requestCount));

        // Build the response
        Message request = new Message(in);
        Message response = new Message(request.getHeader().getID());
        response.addRecord(request.getQuestion(), Section.QUESTION);
        // Add answers as needed
        response.addRecord(Record.fromString(Name.root, Type.A, DClass.IN, 86400, "1.2.3.4", Name.root), Section.ANSWER);

        final Name nameOfIdentifier = concatenate(ACME_CHALLENGE_PREFIX, fromString("FooBArBaz1234", root));
        response.addRecord(Record.fromString(nameOfIdentifier, Type.TXT, DClass.IN, 86400, txtRecord1, Name.root), Section.ANSWER);
        response.addRecord(Record.fromString(nameOfIdentifier, Type.TXT, DClass.IN, 86400, txtRecord2, Name.root), Section.ANSWER);
        response.addRecord(Record.fromString(nameOfIdentifier, Type.TXT, DClass.IN, 86400, txtRecord3, Name.root), Section.ANSWER);

        // Make it timeout, comment this section if a success response is needed
/*
        try {
            Thread.sleep(5000);
        } catch (InterruptedException ex) {
            logger.error("Interrupted");
            return;
        }
*/
        byte[] resp = response.toWire();
        DatagramPacket outdp = new DatagramPacket(resp, resp.length, indp.getAddress(), indp.getPort());
        socket.send(outdp);
    }
}