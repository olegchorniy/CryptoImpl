package crypt.ssl.encoding;

import crypt.ssl.CipherSuite;
import crypt.ssl.messages.*;
import crypt.ssl.messages.Extensions.ExtensionsBuilder;
import crypt.ssl.messages.alert.Alert;
import crypt.ssl.messages.alert.AlertDescription;
import crypt.ssl.messages.alert.AlertLevel;
import crypt.ssl.messages.handshake.*;
import crypt.ssl.utils.Dumper;
import crypt.ssl.utils.IO;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

public abstract class TlsDecoder {

    public static final byte[] EMPTY = new byte[0];

    private TlsDecoder() {
    }

    /*public static TlsRecord readRecord(InputStream in) throws IOException {
        ContentType type = IO.readEnum(in, ContentType.class);
        ProtocolVersion version = IO.readEnum(in, ProtocolVersion.class);

        int length = IO.readInt16(in);
        ByteBuffer recordBody = IO.readBytes(in, length);

        List<TlsMessage> messages = readMessages(recordBody, type);

        checkBufferConsumed(recordBody);

        return new TlsRecord(type, version, messages);
    }*/

    private static List<TlsMessage> readMessages(ByteBuffer recordBody, ContentType type) {
        switch (type) {
            case ALERT:
                return singletonList(readAlert(recordBody));
            case HANDSHAKE:

                List<TlsMessage> messages = new ArrayList<>();

                while (recordBody.hasRemaining()) {
                    messages.add(readHandshake(recordBody));
                }

                return messages;
        }

        //TODO: uncomment
        //throw new IllegalStateException(type + "Other TLS messages not supported");
        System.err.println(type + " TLS message type is not supported");
        return emptyList();
    }

    private static Alert readAlert(ByteBuffer source) {
        AlertLevel level = IO.readEnum(source, AlertLevel.class);
        AlertDescription description = IO.readEnum(source, AlertDescription.class);

        return new Alert(level, description);
    }

    private static HandshakeMessage readHandshake(ByteBuffer source) {
        HandshakeType type = IO.readEnum(source, HandshakeType.class);
        int length = IO.readInt24(source);
        ByteBuffer handshakeBuffer = IO.readAsBuffer(source, length);

        switch (type) {
            case SERVER_HELLO:
                return readServerHello(handshakeBuffer);
            case CERTIFICATE:
                return readCertificate(handshakeBuffer);
            case SERVER_HELLO_DONE:
                return ServerHelloDone.INSTANCE;
        }

        //TODO: uncomment
        //throw new IllegalStateException(type + " handshake message type is not supported for now");
        System.err.println(type + " handshake message type is not supported for now");
        Dumper.dumpToStderr(handshakeBuffer);

        return null;
    }

    private static ServerHello readServerHello(ByteBuffer source) {
        ProtocolVersion serverVersion = IO.readEnum(source, ProtocolVersion.class);
        RandomValue randomValue = readRandomValue(source);
        SessionId sessionId = readSessionId(source);
        CipherSuite cipherSuite = IO.readEnum(source, CipherSuite.class);
        CompressionMethod compressionMethod = IO.readEnum(source, CompressionMethod.class);
        Extensions extensions = readExtensions(source);

        return new ServerHello(
                serverVersion,
                randomValue,
                sessionId,
                cipherSuite,
                compressionMethod,
                extensions
        );
    }

    private static CertificateMessage readCertificate(ByteBuffer source) {

        int certificatesLength = IO.readInt24(source);
        List<ASN1Certificate> certificates = new ArrayList<>();

        while (certificatesLength > 0) {
            ASN1Certificate certificate = readAsn1Certificate(source);

            certificates.add(certificate);

            // subtract 3 bytes for certificate length and the length of the certificate itself
            certificatesLength = certificatesLength - 3 - certificate.getContent().length;
        }

        return new CertificateMessage(certificates);
    }

    private static RandomValue readRandomValue(ByteBuffer source) {
        byte[] randomBytes = IO.readBytes(source, 32);

        return new RandomValue(randomBytes);
    }

    private static SessionId readSessionId(ByteBuffer source) {
        int sessionIdLength = IO.readInt8(source);
        if (sessionIdLength == 0) {
            return new SessionId(EMPTY);
        }

        byte[] sessionIdBytes = IO.readBytes(source, sessionIdLength);

        return new SessionId(sessionIdBytes);
    }

    private static Extensions readExtensions(ByteBuffer source) {
        if (!source.hasRemaining()) {
            return Extensions.empty();
        }

        ExtensionsBuilder builder = Extensions.builder();

        // skip length as we don't need it in current implementation
        IO.readInt16(source);

        while (source.hasRemaining()) {
            int type = IO.readInt16(source);
            int length = IO.readInt16(source);
            byte[] data = (length == 0) ? EMPTY : IO.readBytes(source, length);

            builder.add(type, data);
        }

        return builder.build();
    }

    private static ASN1Certificate readAsn1Certificate(ByteBuffer source) {
        //certificate length cannot be 0
        int certificateLength = IO.readInt24(source);
        byte[] certificateContent = IO.readBytes(source, certificateLength);

        return new ASN1Certificate(certificateContent);
    }

    private static void checkBufferConsumed(ByteBuffer buffer) {
        if (buffer.hasRemaining()) {
            String dump = Dumper.dumpToString(4, buffer);

            throw new IllegalStateException("Message has been read, but not all the data consumed. [\n" + dump + "]");
        }
    }
}
