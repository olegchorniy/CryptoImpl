package crypt.ssl.encoding;

import crypt.ssl.digest.HashAlgorithm;
import crypt.ssl.messages.keyexchange.ServerDHParams;
import crypt.ssl.messages.keyexchange.SignedDHParams;
import crypt.ssl.signature.SignatureAlgorithm;
import crypt.ssl.signature.SignatureAndHashAlgorithm;
import crypt.ssl.utils.IO;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public abstract class KeyExchangeDecoder {

    private KeyExchangeDecoder() {
    }

    public static SignedDHParams readDHKEParams(ByteBuffer buffer) {
        ServerDHParams serverDHParams = readServerDHParams(buffer);

        HashAlgorithm hashAlgorithm = IO.readEnum(buffer, HashAlgorithm.class);
        SignatureAlgorithm signatureAlgorithm = IO.readEnum(buffer, SignatureAlgorithm.class);

        int sigLength = IO.readInt16(buffer);
        ByteBuffer signature = IO.readAsBuffer(buffer, sigLength);

        return new SignedDHParams(
                serverDHParams,
                new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm),
                signature
        );
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
