package crypt.ssl.encoding;

import crypt.ssl.CipherSuite;
import crypt.ssl.messages.*;
import crypt.ssl.messages.alert.Alert;
import crypt.ssl.messages.handshake.*;
import crypt.ssl.utils.IO;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public abstract class TlsEncoder {

    private TlsEncoder() {
    }

    /* -------------------- Public API --------------------- */

    public static void writeRecord(OutputStream out, TlsRecord record) throws IOException {
        IO.writeEnum(out, record.getType());
        IO.writeEnum(out, record.getVersion());

        byte[] recordBody = record.getRecordBody();

        IO.writeOpaque16(out, recordBody);
    }

    public static void writeAlert(OutputStream out, Alert alert) throws IOException {
        IO.writeEnum(out, alert.getLevel());
        IO.writeEnum(out, alert.getDescription());
    }

    public static void writeChangeCipherSpec(OutputStream out, ChangeCipherSpec changeCipherSpec) throws IOException {
        IO.writeInt8(out, changeCipherSpec.getType());
    }

    public static void writeHandshake(OutputStream out, HandshakeMessage handshake) throws IOException {
        ByteBuffer encodedHandshake = encodeHandshake(handshake);

        IO.writeEnum(out, handshake.getType());
        IO.writeInt24(out, encodedHandshake.remaining());
        IO.writeBytes(out, encodedHandshake);
    }

    /* -------------------- Helper encoders --------------------- */

    private static ByteBuffer encodeHandshake(HandshakeMessage handshake) throws IOException {
        HandshakeType type = handshake.getType();

        switch (type) {
            case CLIENT_HELLO:
                return Encoder.writeToBuffer((ClientHello) handshake, TlsEncoder::writeClientHello);

            case CLIENT_KEY_EXCHANGE:
                byte[] exchangeKeys = ((ClientKeyExchange) handshake).getExchangeKeys();
                return ByteBuffer.wrap(exchangeKeys);

            case FINISHED:
                byte[] verifyData = ((Finished) handshake).getVerifyData();
                return ByteBuffer.wrap(verifyData);
        }

        throw new IllegalStateException(handshake.getType() + " handshake message type is not supported for encoding for now");
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

    public static void writeRandom(OutputStream out, RandomValue random) throws IOException {
        IO.writeInt32(out, random.getGmtUnitTime());
        IO.writeBytes(out, random.getRandomBytes());
    }

    private static void writeSessionId(OutputStream out, SessionId sessionId) throws IOException {
        byte[] sessionIdValue = sessionId.getValue();

        IO.writeInt8(out, sessionIdValue.length);
        IO.writeBytes(out, sessionIdValue);
    }

    /* ------------------------------- Reflection magic zone ------------------------------- */

    public static ByteBuffer encode(Object message) throws IOException {
        Method encoderMethod = findEncoder(message.getClass());

        return Encoder.writeToBuffer(message, (out, obj) -> {
            try {
                encoderMethod.invoke(null, out, obj);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private static Method findEncoder(Class<?> clazz) throws IOException {
        List<Method> candidates = new ArrayList<>();

        for (Method method : TlsEncoder.class.getDeclaredMethods()) {
            if (visibilityMatch(method) && parametersMatch(method, clazz)) {
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

    private static boolean visibilityMatch(Method method) {
        int modifiers = method.getModifiers();
        return Modifier.isStatic(modifiers) && Modifier.isPublic(modifiers);
    }

    private static boolean parametersMatch(Method method, Class<?> targetClass) {
        Class<?>[] methodParams = method.getParameterTypes();
        return methodParams.length == 2 &&
                methodParams[0] == OutputStream.class &&
                methodParams[1].isAssignableFrom(targetClass);
    }
}
