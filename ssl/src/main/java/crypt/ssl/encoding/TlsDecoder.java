package crypt.ssl.encoding;

import crypt.ssl.CipherSuite;
import crypt.ssl.Constants;
import crypt.ssl.TlsExceptions;
import crypt.ssl.messages.*;
import crypt.ssl.messages.Extensions.ExtensionsBuilder;
import crypt.ssl.messages.alert.Alert;
import crypt.ssl.messages.alert.AlertDescription;
import crypt.ssl.messages.alert.AlertLevel;
import crypt.ssl.messages.handshake.*;
import crypt.ssl.utils.Assert;
import crypt.ssl.utils.CertificateDecoder;
import crypt.ssl.utils.Dumper;
import crypt.ssl.utils.IO;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public abstract class TlsDecoder {

    //contentType + version + length = 1 + 2 + 2 = 5 bytes
    public static final int TLS_HEADER_LENGTH = 5;

    // level + description = 1 + 1 = 2
    public static final int TLS_ALERT_LENGTH = 2;

    // type = 1 byte
    public static final int TLS_CHANGE_CIPHER_SPEC_LENGTH = 1;

    // handshake type + length = 1 + 3
    public static final int TLS_HANDSHAKE_HEADER_LENGTH = 4;

    private TlsDecoder() {
    }

    public static TlsRecord readRecord(InputStream in) throws IOException {
        ByteBuffer header = IO.readOrNullAsBuffer(in, TLS_HEADER_LENGTH);
        if (header == null) {
            return null;
        }

        ContentType type = IO.readEnum(header, ContentType.class);
        ProtocolVersion version = IO.readEnum(header, ProtocolVersion.class);

        int length = IO.readInt16(header);
        // Yeah, I guess we sure verify record's length before reading this number of bytes from the network, but ... who cares?
        byte[] recordBody = IO.readOrNull(in, length);

        if (recordBody == null) {
            return null;
        }

        return new TlsRecord(type, version, recordBody);
    }

    public static Alert readAlert(ByteBuffer source) {
        AlertLevel level = IO.readEnum(source, AlertLevel.class);
        AlertDescription description = IO.readEnum(source, AlertDescription.class);

        return new Alert(level, description);
    }

    public static ChangeCipherSpec readChangeCipherSpec(ByteBuffer source) {
        int type = IO.readInt8(source);
        return new ChangeCipherSpec(type);
    }

    public static HandshakeMessage readHandshake(ByteBuffer handshakeBuffer) throws IOException {
        HandshakeType type = IO.readEnum(handshakeBuffer, HandshakeType.class);
        int length = IO.readInt24(handshakeBuffer);

        Assert.assertEquals(handshakeBuffer.remaining(), length);

        return readHandshakeOfType(type, handshakeBuffer);
    }

    public static HandshakeMessage readHandshakeOfType(HandshakeType type, ByteBuffer handshakeBuffer) throws IOException {
        switch (type) {
            case SERVER_HELLO:
                return readServerHello(handshakeBuffer);
            case CERTIFICATE:
                return readCertificate(handshakeBuffer);
            case SERVER_KEY_EXCHANGE:
                return new ServerKeyExchange(handshakeBuffer);
            case SERVER_HELLO_DONE:
                return ServerHelloDone.INSTANCE;
            case FINISHED:
                return readFinished(handshakeBuffer);
        }

        Dumper.dumpToStderr(handshakeBuffer);
        throw new IllegalStateException(type + " handshake message type is not supported for now");
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

    private static CertificateMessage readCertificate(ByteBuffer source) throws IOException {

        int certificatesLength = IO.readInt24(source);
        List<X509Certificate> certificates = new ArrayList<>();

        while (certificatesLength > 0) {
            int certificateLength = IO.readInt24(source);
            byte[] certificateContent = IO.readBytes(source, certificateLength);

            certificates.add(decodeCertificate(certificateContent));

            // subtract 3 bytes for certificate length and the length of the certificate itself
            certificatesLength = certificatesLength - 3 - certificateLength;
        }

        return new CertificateMessage(certificates);
    }

    // Used as a wrapper over CertificateDecoder for the exception translation purpose
    private static X509Certificate decodeCertificate(byte[] certBody) throws IOException {
        try {
            return CertificateDecoder.decodeCertificate(certBody);
        } catch (CertificateException e) {
            throw TlsExceptions.decodeError();
        }
    }

    private static RandomValue readRandomValue(ByteBuffer source) {
        int gmtUnixTime = IO.readInt32(source);
        byte[] randomBytes = IO.readBytes(source, 28);

        return new RandomValue(gmtUnixTime, randomBytes);
    }

    private static SessionId readSessionId(ByteBuffer source) {
        int sessionIdLength = IO.readInt8(source);
        if (sessionIdLength == 0) {
            return new SessionId(Constants.EMPTY);
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
            byte[] data = (length == 0) ? Constants.EMPTY : IO.readBytes(source, length);

            builder.add(type, data);
        }

        return builder.build();
    }

    private static Finished readFinished(ByteBuffer source) {
        return new Finished(readAllBytes(source));
    }

    public static ApplicationData readApplicationData(ByteBuffer source) {
        return new ApplicationData(readAllBytes(source));
    }

    private static byte[] readAllBytes(ByteBuffer buffer) {
        return IO.readBytes(buffer, buffer.remaining());
    }

    private static void checkBufferConsumed(ByteBuffer buffer) {
        if (buffer.hasRemaining()) {
            String dump = Dumper.dumpToString(4, buffer);

            throw new IllegalStateException("Message has been read, but not all the data consumed. [\n" + dump + "]");
        }
    }
}
