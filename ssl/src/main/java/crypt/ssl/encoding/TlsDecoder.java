package crypt.ssl.encoding;

import crypt.ssl.messages.*;
import crypt.ssl.messages.alert.Alert;
import crypt.ssl.messages.alert.AlertDescription;
import crypt.ssl.messages.alert.AlertLevel;
import crypt.ssl.messages.handshake.HandshakeMessage;
import crypt.ssl.messages.handshake.HandshakeType;
import crypt.ssl.messages.handshake.ServerHello;
import crypt.ssl.utils.Dumper;
import crypt.ssl.utils.IO;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.List;

import static java.util.Collections.singletonList;

public abstract class TlsDecoder {

    public static final byte[] EMPTY = new byte[0];

    private TlsDecoder() {
    }

    public static TlsRecord readRecord(InputStream in) throws IOException {
        ContentType type = IO.readEnum(in, ContentType.class);
        ProtocolVersion version = IO.readEnum(in, ProtocolVersion.class);

        int length = IO.readInt16(in);
        ByteBuffer recordBody = IO.readBytes(in, length);

        List<TlsMessage> messages = readMessages(recordBody, type);

        checkBufferConsumed(recordBody);

        return new TlsRecord(type, version, messages);
    }

    private static List<TlsMessage> readMessages(ByteBuffer recordBody, ContentType type) {
        switch (type) {
            case ALERT:
                return singletonList(readAlert(recordBody));
            case HANDSHAKE:
                return singletonList(readHandshake(recordBody));
            default:
                throw new IllegalStateException("Other TLS messages not supported");
        }
    }

    private static Alert readAlert(ByteBuffer source) {
        AlertLevel level = IO.readEnum(source, AlertLevel.class);
        AlertDescription description = IO.readEnum(source, AlertDescription.class);

        return new Alert(level, description);
    }

    private static HandshakeMessage readHandshake(ByteBuffer source) {
        HandshakeType type = IO.readEnum(source, HandshakeType.class);
        int length = IO.readInt24(source);

        switch (type) {
            case SERVER_HELLO:
                return readServerHello(length, source);
            default:
                throw new IllegalStateException("Other handshake messages not supported");
        }
    }

    private static ServerHello readServerHello(int length, ByteBuffer source) {
        ProtocolVersion serverVersion = IO.readEnum(source, ProtocolVersion.class);
        RandomValue randomValue = readRandomValue(source);
        SessionId sessionId = readSessionId(source);
        CipherSuite cipherSuite = IO.readEnum(source, CipherSuite.class);
        CompressionMethod compressionMethod = IO.readEnum(source, CompressionMethod.class);

        //TODO: Hmm ... How to determine presence of extensions ? ...
        List<Extension> extensions = null;

        return new ServerHello(
                serverVersion,
                randomValue,
                sessionId,
                cipherSuite,
                compressionMethod,
                extensions
        );
    }

    private static RandomValue readRandomValue(ByteBuffer source) {
        int gmtUnitTime = source.getInt();
        byte[] randomBytes = IO.readBytes(source, 28);

        return new RandomValue(gmtUnitTime, randomBytes);
    }

    private static SessionId readSessionId(ByteBuffer source) {
        int sessionIdLength = IO.readInt8(source);
        if (sessionIdLength == 0) {
            return new SessionId(EMPTY);
        }

        byte[] sessionIdBytes = IO.readBytes(source, sessionIdLength);

        return new SessionId(sessionIdBytes);
    }

    private static void checkBufferConsumed(ByteBuffer buffer) {
        if (buffer.hasRemaining()) {
            String dump = Dumper.dumpToString(buffer);
            throw new IllegalStateException("Message has been read, but not all the data consumed. [\n" + dump + "]");
        }
    }
}
