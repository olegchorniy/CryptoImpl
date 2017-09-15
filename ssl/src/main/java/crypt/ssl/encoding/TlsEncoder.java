package crypt.ssl.encoding;

import crypt.ssl.CipherSuite;
import crypt.ssl.messages.*;
import crypt.ssl.messages.handshake.ClientHello;
import crypt.ssl.messages.handshake.HandshakeMessage;
import crypt.ssl.utils.IO;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

public abstract class TlsEncoder {

    private TlsEncoder() {
    }

    public static void writeRecord(OutputStream out, TlsRecord record) throws IOException {
        IO.writeEnum(out, record.getType());
        IO.writeEnum(out, record.getVersion());

        for (TlsMessage message : record.getMessages()) {

        }
    }

    public static void writeMessage(OutputStream out, ContentType type, TlsMessage message) throws IOException {
        switch (type) {
            case HANDSHAKE:
        }

        //TODO: uncomment
        //throw new IllegalStateException(type + "Other TLS messages not supported");
        System.err.println(type + " TLS message type is not supported");
    }


    private static void writeHandshake(OutputStream out, HandshakeMessage handshake) throws IOException {
        switch (handshake.getType()) {
            case CLIENT_HELLO:
                writeClientHello(out, (ClientHello) handshake);
                break;
        }

        System.err.println(handshake.getType() + " handshake message type is not supported for now");
    }

    private static void writeClientHello(OutputStream out, ClientHello clientHello) throws IOException {
        IO.writeEnum(out, clientHello.getClientVersion());

        writeRandom(out, clientHello.getRandom());
        writeSessionId(out, clientHello.getSessionId());

        List<CipherSuite> cipherSuites = clientHello.getCipherSuites();
        IO.writeInt16(out, cipherSuites.size() * 2 /* each cipher suite takes 2 bytes */);
        IO.writeEnumConstants(out, cipherSuites);

        List<CompressionMethod> compressionMethods = clientHello.getCompressionMethods();
        IO.writeInt8(out, compressionMethods.size() /* each compression method takes 1 byte */);
        IO.writeEnumConstants(out, compressionMethods);
    }

    private static void writeRandom(OutputStream out, RandomValue random) throws IOException {
        IO.writeInt32(out, random.getGmtUnixTime());
        IO.writeBytes(out, random.getRandomBytes());
    }

    private static void writeSessionId(OutputStream out, SessionId sessionId) throws IOException {
        byte[] sessionIdValue = sessionId.getValue();

        IO.writeInt8(out, sessionIdValue.length);
        IO.writeBytes(out, sessionIdValue);
    }

    private static <T> byte[] writeToArray(Encoder<T> encoder, T obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        encoder.encode(bos, obj);

        return bos.toByteArray();
    }

    private interface Encoder<T> {

        void encode(OutputStream out, T t) throws IOException;
    }
}
