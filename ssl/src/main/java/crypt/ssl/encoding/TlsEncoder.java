package crypt.ssl.encoding;

import crypt.ssl.CipherSuite;
import crypt.ssl.messages.*;
import crypt.ssl.messages.alert.Alert;
import crypt.ssl.messages.handshake.*;
import crypt.ssl.utils.IO;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
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

    public static void writeHandshake(OutputStream out, HandshakeMessage handshake) throws IOException {
        ByteBuffer encodedHandshake = encodeHandshake(handshake);

        IO.writeEnum(out, handshake.getContentType());
        IO.writeInt24(out, encodedHandshake.remaining());
        IO.writeBytes(out, encodedHandshake);
    }

    private static ByteBuffer encodeHandshake(HandshakeMessage handshake) throws IOException {
        HandshakeType type = handshake.getType();

        switch (type) {
            case CLIENT_HELLO:
                return writeToBuffer((ClientHello) handshake, TlsEncoder::writeClientHello);

            case CLIENT_KEY_EXCHANGE:
                return ((ClientKeyExchange) handshake).getExchangeKeys();

            case FINISHED:
                return ((Finished) handshake).getVerifyData();
        }

        throw new IllegalStateException(handshake.getType() + " handshake message type is not supported for encoding for now");
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

    public static <T> ByteBuffer writeToBuffer(T obj, Encoder<T> encoder) throws IOException {
        return ByteBuffer.wrap(writeToArray(obj, encoder));
    }

    public static <T> byte[] writeToArray(T obj, Encoder<T> encoder) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        encoder.encode(bos, obj);

        return bos.toByteArray();
    }

    public interface Encoder<T> {

        void encode(OutputStream out, T t) throws IOException;
    }

    /* ------------------------------- Reflection magic zone ------------------------------- */

    public static ByteBuffer encode(Object message) throws IOException {
        Method encoderMethod = findEncoder(message.getClass());

        return writeToBuffer(message, (out, obj) -> {
            try {
                encoderMethod.invoke(null, out, obj);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private static Method findEncoder(Class<?> clazz) throws IOException {
        Class<?>[] targetMethodParameterTypes = {
                OutputStream.class, clazz
        };

        List<Method> candidates = new ArrayList<>();

        for (Method method : TlsEncoder.class.getDeclaredMethods()) {
            if (Modifier.isStatic(method.getModifiers()) &&
                    Arrays.equals(method.getParameterTypes(), targetMethodParameterTypes)) {
                candidates.add(method);
            }
        }

        if (candidates.isEmpty()) {
            throw new RuntimeException("There is no method capable of encoding objects of " + clazz.getName() + " class.");
        }

        if (candidates.size() > 1) {
            throw new RuntimeException("There is more than one method capable of encoding objects of " + clazz.getName() + " class.");
        }

        Method encodeMethod = candidates.iterator().next();
        encodeMethod.setAccessible(true);

        return encodeMethod;
    }
}
