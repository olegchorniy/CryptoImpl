package crypt.ssl.connection;

import crypt.ssl.CipherSuite;
import crypt.ssl.TlsExceptions;
import crypt.ssl.digest.DigestFactory;
import crypt.ssl.digest.HashAlgorithm;
import crypt.ssl.encoding.Encoder;
import crypt.ssl.encoding.TlsDecoder;
import crypt.ssl.encoding.TlsEncoder;
import crypt.ssl.exceptions.NoCloseNotifyException;
import crypt.ssl.exceptions.TlsException;
import crypt.ssl.exceptions.TlsFatalException;
import crypt.ssl.exceptions.TlsUnexpectedMessageException;
import crypt.ssl.keyexchange.DHEKeyExchange;
import crypt.ssl.keyexchange.KeyExchange;
import crypt.ssl.keyexchange.KeyExchangeType;
import crypt.ssl.keyexchange.RSAKeyExchange;
import crypt.ssl.messages.*;
import crypt.ssl.messages.alert.Alert;
import crypt.ssl.messages.alert.AlertDescription;
import crypt.ssl.messages.alert.AlertLevel;
import crypt.ssl.messages.handshake.*;
import crypt.ssl.prf.DigestPRF;
import crypt.ssl.prf.PRF;
import crypt.ssl.utils.*;
import org.bouncycastle.crypto.Digest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;


public class TlsConnection implements Connection {

    private static final List<CompressionMethod> NO_COMPRESSION = Collections.singletonList(CompressionMethod.NULL);
    private static final CipherSuite[] ALL_SUITES;

    static {
        ALL_SUITES = Arrays.stream(CipherSuite.values())
                .filter(suite -> suite != CipherSuite.TLS_NULL_WITH_NULL_NULL)
                .toArray(CipherSuite[]::new);
    }

    // We don't support other TLS versions.
    private final ProtocolVersion version = ProtocolVersion.TLSv12;
    private final Random random = new Random();
    private final TlsContext context;

    private Socket socket;
    private MessageStream messageStream;

    private SecurityParameters parameters = new SecurityParameters();
    private final Session session;

    private ConnectionState state = ConnectionState.NEW;
    private HandshakeState handshakeState = null;
    private boolean fullHandshake;

    private KeyExchange keyExchange;

    private final Buffer applicationDataBuffer = new Buffer();
    // Used to compute hashes for Finished messages
    private Buffer handshakeMessages;

    private TlsInputStream in;
    private TlsOutputStream out;

    /* -------------------------------------------------- */
    private final List<CipherSuite> supportedCipherSuites;

    public TlsConnection() {
        this(ALL_SUITES);
    }

    public TlsConnection(CipherSuite... supportedCipherSuites) {
        this(TlsConfigurer.forSuites(supportedCipherSuites));
    }

    public TlsConnection(Session session) {
        this(TlsConfigurer.forSession(session));
    }

    public TlsConnection(TlsConfigurer configurer) {
        this.supportedCipherSuites = defaultSuitesIfEmpty(configurer.getSuites());

        this.context = new TlsContext();
        this.context.setSecurityParameters(this.parameters);
        this.context.setRandom(this.random);
        this.context.setVersion(this.version);

        Session session = configurer.getSession();
        if (session == null) {
            this.session = new Session();
            this.fullHandshake = true;
        } else {
            this.session = session;
            this.fullHandshake = false;
        }
    }

    private List<CipherSuite> defaultSuitesIfEmpty(List<CipherSuite> suites) {
        if (suites == null || suites.isEmpty()) {
            return Arrays.asList(ALL_SUITES);
        }

        return suites;
    }

    public Session getSession() {
        return session;
    }

    @Override
    public void connect(InetSocketAddress address) throws IOException {
        this.socket = new Socket();
        this.socket.connect(address);

        InputStream in = this.socket.getInputStream();
        OutputStream out = this.socket.getOutputStream();

        this.messageStream = new MessageStream(this.context, in, out);
        this.messageStream.setRecordVersion(this.version);

        performHandshake();
    }

    private void performHandshake() throws IOException {
        // Initialize buffer which holds all the messages sent/received during handshake
        this.handshakeMessages = new Buffer();

        sendClientHello();

        this.state = ConnectionState.HANDSHAKE;
        this.handshakeState = HandshakeState.CLIENT_HELLO_SENT;

        while (this.state != ConnectionState.ESTABLISHED) {
            readAndHandleMessage();

            // This may occur if we receive close_notify alert from the remote peer.
            // No exceptions are thrown in this case, so we have to do this here.
            if (this.state == ConnectionState.CLOSED) {
                throw new IOException("Connection was closed during handshake");
            }
        }
    }

    private void sendClientHello() throws IOException {
        SessionId sessionId = this.fullHandshake ? SessionId.EMPTY : this.session.getSessionId();
        RandomValue randomValue = generateRandom();

        ClientHello clientHello = ClientHello.builder()
                .clientVersion(this.version)
                .random(randomValue)
                .sessionId(sessionId)
                .cipherSuites(this.supportedCipherSuites)
                .compressionMethods(NO_COMPRESSION)
                .extensions(Extensions.empty())
                .build();

        this.parameters.setClientRandom(randomValue);

        sendHandshakeMessage(clientHello);
    }

    private RandomValue generateRandom() {
        return RandomValue.builder()
                .gmtUnitTime(random.nextInt())
                .randomBytes(RandomUtils.getBytes(random, 28))
                .build();
    }

    private void readAndHandleMessage() throws IOException {
        RawMessage message = this.messageStream.readMessage();
        if (message == null) {
            throw new NoCloseNotifyException();
        }

        try {
            handleMessage(message);
        } catch (TlsFatalException alert) {
            sendAlert(AlertLevel.FATAL, alert.getDescription());

            closeInternal();
            throw alert;
        } catch (IOException e) {
            closeInternal();
            throw e;
        }
    }

    private void handleMessage(RawMessage message) throws IOException {
        System.out.println("Connection state = " + this.state);
        System.out.println("Handshake state = " + this.handshakeState);
        System.out.println("ContentType = " + message.getContentType());
        System.out.println("Message length = " + message.getMessageBody().remaining());
        //System.out.println("Message = " + message.toString());

        ByteBuffer body = message.getMessageBody();

        switch (message.getContentType()) {
            case HANDSHAKE:
                byte[] handshakeBytes = Bits.toArray(body);
                HandshakeMessage handshake = TlsDecoder.readHandshake(body);

                if (handshake.getType() != HandshakeType.FINISHED) {
                    saveHandshakeMessage(handshakeBytes);
                }

                handleHandshakeMessage(handshake);

                break;

            case CHANGE_CIPHER_SPEC:
                handleChangeCipherSpec(TlsDecoder.readChangeCipherSpec(body));
                break;

            case APPLICATION_DATA:
                handleApplicationData(TlsDecoder.readApplicationData(body));
                break;

            case ALERT:
                handleAlertMessage(TlsDecoder.readAlert(body));
                break;
        }

        // Ensure that the hole message has been consumed
        // TODO: why we sometimes get into the if block with 01 00 dump (corresponds to close_notify alert) (try with habr in debug).
        if (body.hasRemaining()) {
            System.err.println("Message wasn't consumed");
            System.err.println(message.getContentType());
            Dumper.dumpToStderr(body);
        }
    }

    private void handleHandshakeMessage(HandshakeMessage handshake) throws IOException {
        // Actually, there is a scenario where handshake message can be received after connection has been established.
        // It a case when server sends a HELLO_REQUEST message to renegotiate connection parameters.
        // But this part of the protocol in not supported in current implementation.
        checkConnectionState(ConnectionState.HANDSHAKE);

        Assert.assertNotNull(this.handshakeState);

        switch (this.handshakeState) {
            case CLIENT_HELLO_SENT:
                ServerHello serverHello = safeCast(handshake, ServerHello.class);

                Assert.assertEquals(CompressionMethod.NULL, serverHello.getCompressionMethod());
                Assert.assertEquals(this.version, serverHello.getServerVersion());

                CipherSuite cipherSuite = serverHello.getCipherSuite();
                SessionId sessionId = serverHello.getSessionId();

                this.parameters.setServerRandom(serverHello.getRandom());
                this.parameters.setCipherSuite(cipherSuite);

                if (!this.fullHandshake) {
                    if (!this.session.getSessionId().equals(sessionId)) {
                        // Sever didn't find a match for the supplied sessionId or doesn't want
                        // to perform an abbreviated handshake - fallback to the full handshake.
                        this.fullHandshake = true;
                    } else {
                        // Everything is OK, we can compute sessions keys and wait for the ChangeCipherSpec
                        computeKeys();
                    }
                }

                if (this.fullHandshake) {
                    this.keyExchange = createKeyExchange(cipherSuite.getKeyExchangeType());

                    this.session.setSessionId(sessionId);
                    this.session.setCipherSuite(cipherSuite);
                }

                //TODO: Can we do something useful with extensions?
                //serverHello.getExtensions();

                this.handshakeState = HandshakeState.SERVER_HELLO_RECEIVED;
                return;

            case SERVER_HELLO_RECEIVED:
                // In case of abbreviated handshake we should receive ChangeCipherSpec message after the ServerHello
                Assert.assertTrue(this.fullHandshake);

                // Here we can receive any of the Certificate, ServerKeyExchange, CertificateRequest, ServerHelloDone
                // messages depending on circumstances. But there are several assumptions at this point:
                //  1. We don't support anonymous negotiation, thus Certificate MUST be present.
                //  2. We don't support client authentication, thus we don't expect to receive CertificateRequest.

                CertificateMessage certificate = safeCast(handshake, CertificateMessage.class);

                //TODO: check certificate and store it's necessary parameters

                this.keyExchange.processServerCertificate(certificate.getDecodedCertificate(0));

                this.handshakeState = HandshakeState.CERTIFICATE_RECEIVED;
                return;

            case CERTIFICATE_RECEIVED:
                Assert.assertTrue(this.fullHandshake);

                // Here we should receive either ServerKeyExchange if our key exchange protocol requires that
                // or ServerHelloDone otherwise.

                if (keyExchange.requiresServerKeyExchange()) {
                    ServerKeyExchange serveKeyExchange = safeCast(handshake, ServerKeyExchange.class);

                    keyExchange.processServerKeyExchange(serveKeyExchange);

                    this.handshakeState = HandshakeState.SERVER_KEY_EXCHANGE_RECEIVED;
                    return;
                }

                /*
                otherwise we just fall through to the next section
                (also, probably it is a good idea to execute the following assignment
                this.handshakeState = HandshakeState.SERVER_KEY_EXCHANGE_RECEIVED
                in order to indicate that we don't need this step at all)
                */
            case SERVER_KEY_EXCHANGE_RECEIVED:
                Assert.assertTrue(this.fullHandshake);

                // We can also receive CertificateRequest at this moment but we don't support this scenario.
                // safeCast is called just to ensure that we've really received ServerHelloDone message here.
                safeCast(handshake, ServerHelloDone.class);

                continueFullHandshake();

                this.handshakeState = HandshakeState.FINISHED_SENT;
                return;

            case CHANGE_CIPHER_SPEC_RECEIVED:
                Finished finished = safeCast(handshake, Finished.class);

                verifyFinished(finished);

                if (this.fullHandshake) {
                    handshakeFinished();
                } else {
                    saveHandshakeMessage(Encoder.writeToArray(finished, TlsEncoder::writeHandshake));
                    finishAbbreviatedHandshake();
                }
        }
    }

    private KeyExchange createKeyExchange(KeyExchangeType type) {
        switch (type) {
            case DHE:
                return new DHEKeyExchange(this.context);
            case RSA:
                return new RSAKeyExchange(this.context);
        }

        throw new UnsupportedOperationException(type + " is not supported yet");
    }

    private void continueFullHandshake() throws IOException {
        // And again - we don't support client authentication,
        // so we never sent Certificate and CertificateVerify messages

        sendClientKeyExchange();

        /* We need to calculate keys now because following messages should be encrypted */
        computeSecrets();
        computeKeys();

        sendChangeCipherSpec();

        /* Send first encrypted message */
        sendFinished();
    }

    private void computeSecrets() {
        byte[] preMasterSecret = this.keyExchange.generatePreMasterSecret();

        System.out.println("PreMasterSecret:");
        Dumper.dumpToStdout(preMasterSecret);

        byte[] masterSecret = calculateMasterSecret(preMasterSecret);

        this.session.setMasterSecret(masterSecret);
    }

    private void computeKeys() {
        CipherSuite cipherSuite = parameters.getCipherSuite();

        int macSize = cipherSuite.getMacKeyLength();
        int encryptionKeySize = cipherSuite.getEncryptionKeySize();
        int fixedIvSize = cipherSuite.getFixedIvSize();

        byte[] masterSecret = this.session.getMasterSecret();

        System.out.println("MasterSecret:");
        Dumper.dumpToStdout(masterSecret);

        byte[] keyMaterial = generateKeyMaterial(masterSecret, (macSize + encryptionKeySize + fixedIvSize) * 2);
        ByteBuffer keysBuffer = ByteBuffer.wrap(keyMaterial);

        byte[] clientMacKey = IO.readBytes(keysBuffer, macSize);
        byte[] serverMacKey = IO.readBytes(keysBuffer, macSize);
        byte[] clientEncKey = IO.readBytes(keysBuffer, encryptionKeySize);
        byte[] serverEncKey = IO.readBytes(keysBuffer, encryptionKeySize);
        byte[] clientIv = IO.readBytes(keysBuffer, fixedIvSize);
        byte[] serverIv = IO.readBytes(keysBuffer, fixedIvSize);

        KeyParameters clientKeyParams = new KeyParameters(clientMacKey, clientEncKey, clientIv);
        KeyParameters serverKeyParams = new KeyParameters(serverMacKey, serverEncKey, serverIv);

        System.out.println("clientKeyParams = " + clientKeyParams);
        System.out.println("serverKeyParams = " + serverKeyParams);

        this.parameters.setMasterSecret(masterSecret);
        this.parameters.setClientKeyParameters(clientKeyParams);
        this.parameters.setServerKeyParameters(serverKeyParams);
    }

    private byte[] calculateMasterSecret(byte[] preMasterSecret) {
        byte[] seed = concatRandoms(this.parameters.getClientRandom(), this.parameters.getServerRandom());

        return createPRFInstance().compute(preMasterSecret, "master secret", seed, 48);
    }

    private byte[] generateKeyMaterial(byte[] masterSecret, int size) {
        byte[] seed = concatRandoms(this.parameters.getServerRandom(), this.parameters.getClientRandom());

        return createPRFInstance().compute(masterSecret, "key expansion", seed, size);
    }

    private byte[] concatRandoms(RandomValue first, RandomValue second) {
        return Bits.concat(first.toByteArray(), second.toByteArray());
    }

    private void finishAbbreviatedHandshake() throws IOException {
        sendChangeCipherSpec();
        sendFinished();

        handshakeFinished();
    }

    private void handshakeFinished() {
        this.handshakeState = HandshakeState.DONE;
        this.state = ConnectionState.ESTABLISHED;

        this.handshakeMessages = null;
    }

    private void sendClientKeyExchange() throws IOException {
        byte[] exchangeKeys = this.keyExchange.generateClientKeyExchange();
        sendHandshakeMessage(new ClientKeyExchange(exchangeKeys));
    }

    private void sendFinished() throws IOException {
        byte[] verifyData = computeVerifyData("client finished");
        System.out.println("Client's verifyData = " + Hex.toHex(verifyData));

        sendHandshakeMessage(new Finished(verifyData));
    }

    private void verifyFinished(Finished finished) throws IOException {
        byte[] serverVerifyData = computeVerifyData("server finished");
        System.out.println("Server's verifyData = " + Hex.toHex(serverVerifyData));

        if (!Arrays.equals(serverVerifyData, finished.getVerifyData())) {
            throw TlsExceptions.decryptError();
        }
    }

    private byte[] computeVerifyData(String label) {
        byte[] masterSecret = this.parameters.getMasterSecret();
        byte[] handshakesHash = computeHandshakesHash();
        return createPRFInstance().compute(masterSecret, label, handshakesHash, 12);
    }

    private PRF createPRFInstance() {
        // RFC-5246 states that SHA-256 should be used unless other PRF is defined by a negotiated cipher suite.
        return new DigestPRF(HashAlgorithm.SHA256);
    }

    /* ---------------------- ChangeCipherSpec related methods ------------------------ */

    private void handleChangeCipherSpec(ChangeCipherSpec changeCipherSpec) throws IOException {
        // We expect to receive ChangeCipherSpec message in two cases:
        //   1. After we sent a Finished message in case of a full handshake
        //   2. After the server sent us a ServerHello message in case of an abbreviated handshake
        // Anyway, current connection state should be HANDSHAKE.

        checkConnectionState(ConnectionState.HANDSHAKE);

        if (this.fullHandshake) {
            checkHandshakeState(HandshakeState.FINISHED_SENT);
        } else {
            checkHandshakeState(HandshakeState.SERVER_HELLO_RECEIVED);
        }

        Assert.assertEquals(changeCipherSpec.getType(), 1);

        // Initialize reading encryption, since all the following inbound messages will be encrypted
        this.messageStream.initReadEncryption(this.parameters.getServerKeyParameters());

        this.handshakeState = HandshakeState.CHANGE_CIPHER_SPEC_RECEIVED;
    }

    private void sendChangeCipherSpec() throws IOException {
        sendMessage(ChangeCipherSpec.INSTANCE, TlsEncoder::writeChangeCipherSpec);

        // Initializer writing encryption, since all the following outbound messages should be encrypted
        this.messageStream.initWriteEncryption(this.parameters.getClientKeyParameters());
    }

    private void handleApplicationData(ApplicationData applicationData) throws IOException {
        this.applicationDataBuffer.putBytes(applicationData.getData());
    }

    private void handleAlertMessage(Alert alert) throws IOException {

        AlertLevel level = alert.getLevel();
        AlertDescription description = alert.getDescription();

        if (level == AlertLevel.FATAL) {
            closeInternal();

            throw new IOException("Fatal alert received - " + alert.getDescription());
        } else {
            // TODO: that's all? Can we do anything else with alerts?
            System.err.println("Warning alert received - " + alert);
        }

        if (description == AlertDescription.CLOSE_NOTIFY) {
            closeInternal();
        }
    }

    private void closeInternal() throws IOException {
        if (this.state != ConnectionState.CLOSED) {
            this.state = ConnectionState.CLOSED;

            run(() -> sendAlert(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY));
            run(() -> this.socket.close());

            //TODO: what about other kinds of cleanup?
        }
    }

    /*
     * Several convenient adapter methods.
     */

    private void sendHandshakeMessage(HandshakeMessage handshakeMessage) throws IOException {
        sendMessage(handshakeMessage, TlsEncoder::writeHandshake);
    }

    private void sendAlert(AlertLevel level, AlertDescription description) throws IOException {
        sendMessage(new Alert(level, description), TlsEncoder::writeAlert);
    }

    /**
     * Helper method which serves as an adapter to MessageStream.
     */
    private <T extends TlsMessage> void sendMessage(T payload, Encoder<? super T> encoder) throws IOException {
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        encoder.encode(message, payload);

        ContentType type = payload.getContentType();
        byte[] messageBytes = message.toByteArray();

        if (type == ContentType.HANDSHAKE) {
            // Update digest which will be used to form a Finished message.
            saveHandshakeMessage(messageBytes);
        }

        doSendMessage(type, messageBytes);
    }

    /**
     * Perform actual sending to the underlying message stream and handles some types of exceptions.
     */
    private void doSendMessage(ContentType type, byte[] body) throws IOException {
        if (this.state == ConnectionState.CLOSED) {
            throw new IOException("Connection is closed");
        }

        try {
            this.messageStream.writeMessage(type, ByteBuffer.wrap(body));
        } catch (TlsFatalException alert) {
            sendAlert(AlertLevel.FATAL, alert.getDescription());

            closeInternal();
            throw alert;
        } catch (IOException e) {
            closeInternal();
            throw e;
        }
    }

    @Override
    public InputStream getInput() throws IOException {
        if (this.in == null) {
            this.in = new TlsInputStream();
        }

        return this.in;
    }

    @Override
    public OutputStream getOutput() throws IOException {
        if (this.out == null) {
            this.out = new TlsOutputStream();
        }

        return this.out;
    }

    @Override
    public void close() throws IOException {
        closeInternal();
    }

    private void saveHandshakeMessage(byte[] bytes) {
        if (this.handshakeMessages != null) {
            this.handshakeMessages.putBytes(bytes);
        }
    }

    private byte[] computeHandshakesHash() {
        // Hash function should be consistent with PRF used.
        Digest digest = DigestFactory.createDigest(HashAlgorithm.SHA256);

        byte[] handshakesBytes = Bits.toArray(this.handshakeMessages.peekBytes());
        digest.update(handshakesBytes, 0, handshakesBytes.length);

        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);

        return out;
    }

    private static <T> T safeCast(Object object, Class<T> clazz) throws TlsException {
        if (clazz.isInstance(object)) {
            return clazz.cast(object);
        }

        throw new TlsUnexpectedMessageException();
    }

    private void checkConnectionState(ConnectionState expectedState) throws TlsException {
        if (this.state != expectedState) {
            throw new TlsUnexpectedMessageException();
        }
    }

    private void checkHandshakeState(HandshakeState expectedState) throws TlsException {
        if (this.handshakeState != expectedState) {
            throw new TlsUnexpectedMessageException();
        }
    }

    private static void run(IOAction action) {
        try {
            action.run();
        } catch (IOException ignore) {
        }
    }

    private interface IOAction {
        void run() throws IOException;
    }

    private enum ConnectionState {
        NEW,
        HANDSHAKE,
        ESTABLISHED,
        CLOSED
    }

    private enum HandshakeState {
        CLIENT_HELLO_SENT,
        SERVER_HELLO_RECEIVED,
        CHANGE_CIPHER_SPEC_RECEIVED,
        CERTIFICATE_RECEIVED,
        SERVER_KEY_EXCHANGE_RECEIVED,
        DONE,
        FINISHED_SENT
    }

    private class TlsInputStream extends InputStream {

        private byte[] inBuff = new byte[1];

        @Override
        public int available() throws IOException {
            return applicationDataBuffer.available();
        }

        @Override
        public int read() throws IOException {
            while (applicationDataBuffer.isEmpty()) {
                if (state == ConnectionState.CLOSED) {
                    return -1;
                }

                readAndHandleMessage();
            }

            applicationDataBuffer.getBytes(inBuff);

            return inBuff[0] & 0xFF;
        }

        @Override
        public void close() throws IOException {
            closeInternal();
        }
    }

    private class TlsOutputStream extends OutputStream {

        private final byte[] outBuff = new byte[1];

        @Override
        public void write(int b) throws IOException {
            outBuff[0] = (byte) b;
            write(outBuff, 0, 1);
        }

        @Override
        public void write(byte[] buff, int off, int len) throws IOException {
            doSendMessage(ContentType.APPLICATION_DATA, Arrays.copyOfRange(buff, off, off + len));
        }

        @Override
        public void close() throws IOException {
            closeInternal();
        }
    }
}
