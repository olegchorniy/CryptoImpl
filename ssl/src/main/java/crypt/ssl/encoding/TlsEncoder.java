package crypt.ssl.encoding;

import crypt.ssl.CipherSuite;
import crypt.ssl.messages.*;
import crypt.ssl.messages.alert.Alert;
import crypt.ssl.messages.handshake.ClientHello;
import crypt.ssl.utils.IO;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.List;

public abstract class TlsEncoder {

    private TlsEncoder() {
    }

    public static void writeRecord(OutputStream out, TlsRecord record) throws IOException {
        IO.writeEnum(out, record.getType());
        IO.writeEnum(out, record.getVersion());

        ByteBuffer recordBody = record.getRecordBody();

        IO.writeInt16(out, recordBody.remaining());
        IO.writeBytes(out, recordBody);
    }

    public static void writeClientHello(OutputStream out, ClientHello clientHello) throws IOException {
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
        IO.writeInt32(out, random.getGmtUnitTime());
        IO.writeBytes(out, random.getRandomBytes());
    }

    private static void writeSessionId(OutputStream out, SessionId sessionId) throws IOException {
        byte[] sessionIdValue = sessionId.getValue();

        IO.writeInt8(out, sessionIdValue.length);
        IO.writeBytes(out, sessionIdValue);
    }

    public static void writeAlert(OutputStream out, Alert alert) throws IOException {
        IO.writeEnum(out, alert.getLevel());
        IO.writeEnum(out, alert.getDescription());
    }

    public static void writeChangeCipherSpec(OutputStream out, ChangeCipherSpec changeCipherSpec) throws IOException {
        IO.writeInt8(out, changeCipherSpec.getType());
    }

    public static <T> ByteBuffer writeToBuffer(Encoder<T> encoder, T obj) throws IOException {
        return ByteBuffer.wrap(writeToArray(encoder, obj));
    }

    public static <T> byte[] writeToArray(Encoder<T> encoder, T obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        encoder.encode(bos, obj);

        return bos.toByteArray();
    }

    public interface Encoder<T> {

        void encode(OutputStream out, T t) throws IOException;
    }
}
