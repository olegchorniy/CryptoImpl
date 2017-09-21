package crypt.ssl.encoding;

import crypt.ssl.messages.keyexchange.ServerDHParams;
import crypt.ssl.messages.keyexchange.SignedDHParams;
import crypt.ssl.utils.IO;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public abstract class KeyExchangeDecoder {

    private KeyExchangeDecoder() {
    }

    public static SignedDHParams readDHKEParams(ByteBuffer buffer) {
        ServerDHParams serverDHParams = readServerDHParams(buffer);

        int sigLength = IO.readInt16(buffer);
        ByteBuffer signature = IO.readAsBuffer(buffer, sigLength);

        return new SignedDHParams(serverDHParams, signature);
    }

    private static ServerDHParams readServerDHParams(ByteBuffer buffer) {
        BigInteger p = readBigInteger16(buffer);
        BigInteger g = readBigInteger16(buffer);
        BigInteger Ys = readBigInteger16(buffer);

        return new ServerDHParams(p, g, Ys);
    }

    private static BigInteger readBigInteger16(ByteBuffer buffer) {
        int length = IO.readInt16(buffer);
        byte[] mag = IO.readBytes(buffer, length);

        return new BigInteger(1, mag);
    }
}
